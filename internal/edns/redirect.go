package edns

import (
	"fmt"
	"net/http"
	"strings"
)

func sameOriginHTTPSRedirect(label, originHost string) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many %s redirects", label)
		}
		if request.URL.Scheme != "https" {
			return fmt.Errorf("%s redirect changed to a non-HTTPS scheme", label)
		}
		if !strings.EqualFold(request.URL.Hostname(), originHost) {
			return fmt.Errorf("%s redirect changed authentication domain", label)
		}
		return nil
	}
}
