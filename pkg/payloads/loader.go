package payloads

import (
	"arfa/pkg/models"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
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

// Fingerprint computes a deterministic identity for the exact corpus state
// represented by ps (TD #16 — Payload corpus reproducibility/versioning).
//
// It is built from each payload's already-deterministic identity fields
// (ID, Category, CorpusName, CorpusCategory, FileType) rather than from
// Source: Source is the absolute filesystem path the corpus happened to be
// checked out to on this machine, which is not part of the corpus's
// *content* state and would make the fingerprint non-reproducible across
// different checkouts/environments of the identical corpus - contrary to
// TD #16's reproducibility purpose.
//
// Load()'s own traversal order is not guaranteed (see loader_test.go's
// TestLoadCorpusMetadataDeterministicAcrossLoads), so every payload's
// identity line is computed independently and the resulting lines are
// sorted before hashing: two loads of the same corpus content therefore
// always produce the same fingerprint, regardless of traversal order, and
// any change to corpus content (a payload added, removed, or changed)
// changes the fingerprint. Fingerprint does not read the filesystem itself
// and does not alter ps or any Payload field.
func Fingerprint(ps []models.Payload) string {
	lines := make([]string, 0, len(ps))
	for _, p := range ps {
		lines = append(lines, p.ID+"|"+p.Category+"|"+p.CorpusName+"|"+p.CorpusCategory+"|"+p.FileType)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func Group(in []models.Payload) map[string][]models.Payload {
	m := map[string][]models.Payload{}
	for _, p := range in {
		m[p.Category] = append(m[p.Category], p)
	}
	return m
}
