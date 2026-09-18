package payloads

import (
	"arfa/pkg/models"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

var dirs = map[string][]string{
	"XSS": {"XSS Injection"}, "SQLi": {"SQL Injection"}, "LFI": {"File Inclusion", "Directory Traversal"}, "RCE": {"Command Injection"}, "SSRF": {"Server Side Request Forgery"}, "SSTI": {"Server Side Template Injection"}, "XXE": {"XXE Injection"}, "CRLF": {"CRLF Injection"}, "Open Redirect": {"Open Redirect"},
}

func Load(root string) ([]models.Payload, error) {
	var out []models.Payload
	seen := map[string]bool{}
	// TD #6: corpusName is the corpus root's own base directory name -
	// deterministic, already available from the root argument, and not
	// an inferred value.
	corpusName := filepath.Base(filepath.Clean(root))
	for cat, names := range dirs {
		for _, name := range names {
			d := filepath.Join(root, name)
			err := filepath.Walk(d, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				if ext != ".txt" && ext != ".md" {
					return nil
				}
				f, e := os.Open(path)
				if e != nil {
					return nil
				}
				defer f.Close()
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "|") || len(line) > 2048 {
						continue
					}
					h := sha256.Sum256([]byte(cat + "|" + line))
					id := hex.EncodeToString(h[:8])
					if !seen[id] {
						seen[id] = true
						// TD #6: name (the corpus's own vulnerability-class
						// directory, e.g. "XSS Injection") and ext (already
						// computed above by the existing file-type filter)
						// are both already-known, deterministic corpus
						// structure - not inferred or heuristic.
						out = append(out, models.Payload{
							ID:             id,
							Category:       cat,
							Value:          line,
							Source:         path,
							CorpusName:     corpusName,
							CorpusCategory: name,
							FileType:       strings.TrimPrefix(ext, "."),
						})
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}
func Group(in []models.Payload) map[string][]models.Payload {
	m := map[string][]models.Payload{}
	for _, p := range in {
		m[p.Category] = append(m[p.Category], p)
	}
	return m
}
