package report

import (
	"arfa/pkg/models"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
)

func JSON(path string, r models.ScanResult) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0644)
}
func HTML(path string, r models.ScanResult) error {
	const t = `<!doctype html><html><head><meta charset="utf-8"><title>Arfa VAPT Report</title><style>body{font-family:system-ui;background:#101216;color:#eee;max-width:1200px;margin:30px auto;padding:0 20px}.card{background:#1b1f27;padding:18px;border-radius:12px;margin:14px 0}.Critical{border-left:6px solid #f33}.High{border-left:6px solid #f80}.Medium{border-left:6px solid #fc3}.Low{border-left:6px solid #4c6}.mono{white-space:pre-wrap;font-family:monospace}.vstatus{display:inline-block;padding:2px 8px;border-radius:6px;font-size:0.85em;background:#333}</style></head><body><h1>🦁 Arfa VAPT</h1><p>{{.Target}} — {{.Mode}}</p><div class="card">Reachability: <b>{{.Reachability.Status}}</b> — {{.Reachability.Reason}}<br>Selected URL: {{.Reachability.SelectedURL}}<br>Requests: {{.Stats.Requests}} | Errors: {{.Stats.Errors}} | Endpoints: {{.Stats.Endpoints}} | Duration: {{.Stats.DurationMS}} ms | Adaptive budget: {{.Stats.AdaptiveBudget}}</div>{{range .Findings}}<div class="card {{.Severity}}"><h2>{{.Name}} — {{.Severity}} <span class="vstatus">{{.VerificationStatus}}</span></h2><p><b>Category:</b> {{.Category}} | <b>Parameter:</b> {{.Parameter}} | <b>Confidence:</b> {{.Confidence}}</p><p><b>Evidence:</b> {{.Evidence}}</p>{{if .VerificationDetail}}<p><b>Verification:</b> {{.VerificationDetail}}</p>{{end}}<p><b>PoC:</b></p><div class="mono">{{.PoC}}</div><p><b>Remediation:</b> {{.Remediation}}</p></div>{{else}}<div class="card">No findings.</div>{{end}}</body></html>`
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return template.Must(template.New("r").Parse(t)).Execute(f, r)
}
func Markdown(path string, r models.ScanResult) error {
	f, e := os.Create(path)
	if e != nil {
		return e
	}
	defer f.Close()
	fmt.Fprintf(f, "# Arfa VAPT\n\nTarget: `%s`\nMode: `%s`\nRequests: %d\n\n", r.Target, r.Mode, r.Stats.Requests)
	for _, v := range r.Findings {
		fmt.Fprintf(f, "## %s (%s) [%s]\n- Parameter: `%s`\n- Evidence: %s\n- PoC: `%s`\n\n", v.Name, v.Severity, v.VerificationStatus, v.Parameter, v.Evidence, v.PoC)
	}
	return nil
}
