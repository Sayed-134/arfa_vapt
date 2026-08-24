// Package config loads ARFA's small, human-editable key=value configuration
// file. CLI flags remain the final authority so existing automation is not
// changed by introducing configuration files.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Mode     string
	Workers  int
	Rate     float64
	MaxPages int
	Timeout  time.Duration
}

func Defaults() Config {
	return Config{Mode: "standard", Workers: 10, Rate: 10, MaxPages: 30, Timeout: 12 * time.Second}
}

// Load returns defaults when path is empty. Unknown keys are rejected so a
// configuration typo cannot silently weaken or alter a scan.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	line := 0
	for s.Scan() {
		line++
		raw := strings.TrimSpace(s.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			return cfg, fmt.Errorf("config %s:%d: expected key=value", path, line)
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "mode":
			cfg.Mode = value
		case "workers":
			cfg.Workers, err = strconv.Atoi(value)
		case "rate":
			cfg.Rate, err = strconv.ParseFloat(value, 64)
		case "max_pages":
			cfg.MaxPages, err = strconv.Atoi(value)
		case "timeout_seconds":
			var seconds int
			seconds, err = strconv.Atoi(value)
			cfg.Timeout = time.Duration(seconds) * time.Second
		default:
			return cfg, fmt.Errorf("config %s:%d: unknown key %q", path, line, key)
		}
		if err != nil {
			return cfg, fmt.Errorf("config %s:%d: invalid %s: %w", path, line, key, err)
		}
	}
	if err := s.Err(); err != nil {
		return cfg, err
	}
	if cfg.Workers < 1 || cfg.Rate <= 0 || cfg.MaxPages < 1 || cfg.Timeout <= 0 {
		return cfg, fmt.Errorf("config %s: workers, rate, max_pages and timeout_seconds must be positive", path)
	}
	return cfg, nil
}
