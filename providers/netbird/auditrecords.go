package netbird

import "github.com/StackExchange/dnscontrol/v4/models"

// AuditRecords returns a list of errors corresponding to the records
// that aren't supported by this provider. If all records are
// supported, an empty list is returned.
//
// Netbird only supports A, AAAA, and CNAME record types.
// Unsupported record types will be rejected by the normalize validation
// based on the provider capabilities defined in the features map.
func AuditRecords(records []*models.RecordConfig) []error {
	return nil
}
