package netbird

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/providers"
)

/*
Netbird API DNS provider:

Info required in `creds.json`:
   - token: Netbird API token

Optional:
   - api_base: Override the default API base URL (default: https://api.netbird.io)
*/

// NewNetbird creates a new Netbird provider.
func NewNetbird(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	token := strings.TrimSpace(m["token"])
	if token == "" {
		return nil, errors.New("missing Netbird API token")
	}

	apiBase := strings.TrimSpace(m["api_base"])
	if apiBase == "" {
		apiBase = defaultAPIBase
	}

	api := &netbirdProvider{
		apiBase:    apiBase,
		token:      token,
		httpClient: newHTTPClient(),
	}

	return api, nil
}

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanConcur:              providers.Cannot("Not tested for concurrent operations"),
	providers.CanGetZones:            providers.Can(),
	providers.CanUseCAA:              providers.Cannot("Netbird only supports A, AAAA, and CNAME records"),
	providers.CanUsePTR:              providers.Cannot("Netbird only supports A, AAAA, and CNAME records"),
	providers.CanUseSRV:              providers.Cannot("Netbird only supports A, AAAA, and CNAME records"),
	providers.CanUseSSHFP:            providers.Cannot("Netbird only supports A, AAAA, and CNAME records"),
	providers.CanUseTLSA:             providers.Cannot("Netbird only supports A, AAAA, and CNAME records"),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocDualHost:            providers.Cannot("Netbird is a private DNS service, not suitable for dual hosting"),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	const providerName = "NETBIRD"
	const providerMaintainer = "@slacking0564"
	fns := providers.DspFuncs{
		Initializer:   NewNetbird,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterMaintainer(providerName, providerMaintainer)
}

// GetNameservers returns the nameservers for a domain.
// Netbird uses its own private DNS, so we return empty nameservers.
func (c *netbirdProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	// Netbird is a private DNS service without public nameservers
	return nil, nil
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (c *netbirdProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	// Find the zone for this domain
	zone, err := c.findZoneByDomain(domain)
	if err != nil {
		return nil, err
	}
	if zone == nil {
		return nil, fmt.Errorf("zone not found for domain: %s", domain)
	}

	// Get records for this zone
	records, err := c.listRecords(zone.ID)
	if err != nil {
		return nil, err
	}

	// Convert to DNSControl format
	existingRecords := make([]*models.RecordConfig, 0, len(records))
	for _, r := range records {
		rc, err := toRecordConfig(domain, &r)
		if err != nil {
			return nil, err
		}
		existingRecords = append(existingRecords, rc)
	}

	return existingRecords, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (c *netbirdProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, int, error) {
	// Find the zone for this domain
	zone, err := c.findZoneByDomain(dc.Name)
	if err != nil {
		return nil, 0, err
	}
	if zone == nil {
		return nil, 0, fmt.Errorf("zone not found for domain: %s", dc.Name)
	}

	var corrections []*models.Correction

	instructions, actualChangeCount, err := diff2.ByRecord(existingRecords, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	for _, inst := range instructions {
		switch inst.Type {
		case diff2.REPORT:
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
			})
			continue

		case diff2.CREATE:
			rec := inst.New[0]
			req := toRecordRequest(rec)
			zoneID := zone.ID
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
				F: func() error {
					_, err := c.createRecord(zoneID, req)
					return err
				},
			})

		case diff2.CHANGE:
			oldRec := inst.Old[0]
			newRec := inst.New[0]
			recordID := oldRec.Original.(*DNSRecord).ID
			req := toRecordRequest(newRec)
			zoneID := zone.ID
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
				F: func() error {
					_, err := c.updateRecord(zoneID, recordID, req)
					return err
				},
			})

		case diff2.DELETE:
			oldRec := inst.Old[0]
			recordID := oldRec.Original.(*DNSRecord).ID
			zoneID := zone.ID
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
				F: func() error {
					return c.deleteRecord(zoneID, recordID)
				},
			})

		default:
			panic(fmt.Sprintf("unhandled instruction type: %s", inst.Type))
		}
	}

	return corrections, actualChangeCount, nil
}

// ListZones returns all the zones in the account.
func (c *netbirdProvider) ListZones() ([]string, error) {
	zones, err := c.listZones()
	if err != nil {
		return nil, err
	}

	domains := make([]string, 0, len(zones))
	for _, z := range zones {
		domains = append(domains, z.Domain)
	}
	return domains, nil
}

// EnsureZoneExists creates a zone if it does not exist.
func (c *netbirdProvider) EnsureZoneExists(domain string, metadata map[string]string) error {
	zone, err := c.findZoneByDomain(domain)
	if err != nil {
		return err
	}

	if zone != nil {
		// Zone already exists
		return nil
	}

	// Create the zone
	req := ZoneRequest{
		Name:               domain,
		Domain:             domain,
		Enabled:            true,
		EnableSearchDomain: false,
		DistributionGroups: []string{}, // Empty by default, can be configured via metadata
	}

	_, err = c.createZone(req)
	return err
}

// findZoneByDomain finds a zone by its domain name
func (c *netbirdProvider) findZoneByDomain(domain string) (*Zone, error) {
	zones, err := c.listZones()
	if err != nil {
		return nil, err
	}

	for i := range zones {
		if zones[i].Domain == domain {
			return &zones[i], nil
		}
	}

	return nil, nil
}

// toRecordConfig converts a Netbird DNS record to a DNSControl RecordConfig
func toRecordConfig(domain string, r *DNSRecord) (*models.RecordConfig, error) {
	rc := &models.RecordConfig{
		Type:     r.Type,
		TTL:      r.TTL,
		Original: r,
	}

	// The Name field in Netbird is the FQDN
	// We need to extract the label (subdomain part)
	rc.SetLabelFromFQDN(r.Name, domain)

	target := r.Content
	// For CNAME records, ensure target ends with a dot
	if r.Type == "CNAME" && !strings.HasSuffix(target, ".") {
		target = target + "."
	}

	if err := rc.SetTarget(target); err != nil {
		return nil, err
	}

	return rc, nil
}

// toRecordRequest converts a DNSControl RecordConfig to a Netbird DNS record request
func toRecordRequest(rc *models.RecordConfig) DNSRecordRequest {
	target := rc.GetTargetField()

	// Remove trailing dot from CNAME targets for Netbird API
	if rc.Type == "CNAME" && strings.HasSuffix(target, ".") {
		target = strings.TrimSuffix(target, ".")
	}

	return DNSRecordRequest{
		Name:    rc.GetLabelFQDN(),
		Type:    rc.Type,
		Content: target,
		TTL:     rc.TTL,
	}
}
