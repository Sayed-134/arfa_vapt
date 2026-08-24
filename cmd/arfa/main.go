package main

import (
	"arfa/pkg/config"
	"arfa/pkg/db"
	"arfa/pkg/detectors"
	"arfa/pkg/report"
	"arfa/pkg/scanner"
	"arfa/pkg/scope"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var target, payloadDir, out, mode, configPath string
	var workers int
	var rate float64
	var pages int
	var timeout time.Duration
	var authorized, verbose, preflightOnly, skipPreflight bool
	flag.StringVar(&target, "target", "", "authorized target URL")
	flag.StringVar(&payloadDir, "payload-dir", "./payloads-database/PayloadsAllTheThings-master", "Payload repository root")
	flag.StringVar(&out, "out", "./reports-output", "report directory")
	flag.StringVar(&mode, "mode", "standard", "quick|standard|deep")
	flag.StringVar(&configPath, "config", "./configs/default.conf", "path to key=value scan configuration")
	flag.IntVar(&workers, "workers", 10, "worker count")
	flag.Float64Var(&rate, "rate", 10, "starting requests/sec")
	flag.IntVar(&pages, "max-pages", 30, "crawler page limit")
	flag.DurationVar(&timeout, "timeout", 12*time.Second, "per-request timeout (for example 12s)")
	flag.BoolVar(&authorized, "i-have-authorization", false, "required acknowledgement for active scanning")
	flag.BoolVar(&verbose, "verbose", false, "verbose logging")
	flag.BoolVar(&preflightOnly, "preflight-only", false, "run reachability checks and do not scan")
	flag.BoolVar(&skipPreflight, "skip-preflight", false, "skip reachability checks (not recommended)")
	flag.Parse()
	if target == "" {
		log.Fatal("-target is required")
	}
	fileCfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal(err)
	}
	provided := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if !provided["mode"] {
		mode = fileCfg.Mode
	}
	if !provided["workers"] {
		workers = fileCfg.Workers
	}
	if !provided["rate"] {
		rate = fileCfg.Rate
	}
	if !provided["max-pages"] {
		pages = fileCfg.MaxPages
	}
	if !provided["timeout"] {
		timeout = fileCfg.Timeout
	}
	scanScope, err := scope.Authorize(target, authorized, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		log.Fatal(err)
	}
	var m scanner.Mode
	switch strings.ToLower(mode) {
	case "quick":
		m = scanner.Quick
	case "deep":
		m = scanner.Deep
	default:
		m = scanner.Standard
	}
	reg := detectors.NewRegistry(detectors.XSS{}, detectors.SQLi{}, detectors.LFI{}, detectors.RCE{}, detectors.SSTI{}, detectors.SSRF{}, detectors.XXE{}, detectors.CRLF{}, detectors.Redirect{})
	s := scanner.New(scanner.Config{Workers: workers, Rate: rate, Timeout: timeout, Mode: m, MaxPages: pages, Verbose: verbose, PreflightOnly: preflightOnly, SkipPreflight: skipPreflight, Scope: scanScope}, reg)
	if !preflightOnly {
		if err := s.LoadPayloads(payloadDir); err != nil {
			log.Fatal(err)
		}
		s.LogStats()
	}
	r, err := s.Scan(context.Background(), target)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Reachability: %s (%s) | Findings: %d | Requests: %d | Duration: %d ms | Adaptive budget: %d/%d\n", r.Reachability.Status, r.Reachability.Reason, len(r.Findings), r.Stats.Requests, r.Stats.DurationMS, r.Stats.AdaptiveBudget, workers)
	if err := report.JSON(filepath.Join(out, "scan_results.json"), r); err != nil {
		log.Fatal(err)
	}
	if err := report.HTML(filepath.Join(out, "scan_report.html"), r); err != nil {
		log.Fatal(err)
	}
	if st, err := db.Open(filepath.Join(out, "scan_history.json")); err == nil {
		_ = st.Save(r)
	}
	if r.Reachability.Status != "reachable" && !skipPreflight {
		os.Exit(3)
	}
}
