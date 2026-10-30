package classify

import (
	"strings"

	"nazr/api/internal/ua"
)

// CohortKey returns "<uaFamily>|<ja4Family>", grouping requests by claimed
// browser family and the TLS family its JA4 fingerprint maps to.
func CohortKey(userAgent string, brave bool, ja4Families []string) string {
	tls := ""
	if len(ja4Families) > 0 {
		tls = TLSFamily(strings.ToLower(ja4Families[0]))
	}
	return ua.FamilyWithBrave(userAgent, brave) + "|" + tls
}
