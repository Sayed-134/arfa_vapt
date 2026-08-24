// Package scope records the operator acknowledgement required before ARFA can
// perform active requests. It deliberately does not infer authorization from
// a URL; the explicit CLI acknowledgement remains mandatory.
package scope

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"arfa/pkg/models"
)

func Authorize(target string, acknowledged bool, now time.Time) (models.ScanScope, error) {
	if !acknowledged {
		return models.ScanScope{}, fmt.Errorf("refusing active scan: pass -i-have-authorization for an authorized target")
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") {
		return models.ScanScope{}, fmt.Errorf("target must be an absolute http(s) URL")
	}
	return models.ScanScope{Authorized: true, AuthorizationMethod: "cli_acknowledgement", AuthorizedAt: now.UTC().Format(time.RFC3339)}, nil
}
