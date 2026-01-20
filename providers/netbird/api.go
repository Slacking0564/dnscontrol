package netbird

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultAPIBase = "https://api.netbird.io"

// netbirdProvider is the handle for API operations
type netbirdProvider struct {
	apiBase    string
	token      string
	httpClient *http.Client
}

// Zone represents a Netbird DNS zone
type Zone struct {
	ID                 string      `json:"id"`
	Name               string      `json:"name"`
	Domain             string      `json:"domain"`
	Enabled            bool        `json:"enabled"`
	EnableSearchDomain bool        `json:"enable_search_domain"`
	DistributionGroups []string    `json:"distribution_groups"`
	Records            []DNSRecord `json:"records,omitempty"`
}

// ZoneRequest represents the request body for creating/updating a zone
type ZoneRequest struct {
	Name               string   `json:"name"`
	Domain             string   `json:"domain"`
	Enabled            bool     `json:"enabled"`
	EnableSearchDomain bool     `json:"enable_search_domain"`
	DistributionGroups []string `json:"distribution_groups"`
}

// DNSRecord represents a Netbird DNS record
type DNSRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     uint32 `json:"ttl"`
}

// DNSRecordRequest represents the request body for creating/updating a DNS record
type DNSRecordRequest struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     uint32 `json:"ttl"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// listZones returns all DNS zones in the account
func (c *netbirdProvider) listZones() ([]Zone, error) {
	var zones []Zone
	body, err := c.doRequest("GET", "/api/dns/zones", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}

	if err := json.Unmarshal(body, &zones); err != nil {
		return nil, fmt.Errorf("failed to parse zones response: %w", err)
	}

	return zones, nil
}

// getZone returns a specific zone by ID
func (c *netbirdProvider) getZone(zoneID string) (*Zone, error) {
	var zone Zone
	body, err := c.doRequest("GET", fmt.Sprintf("/api/dns/zones/%s", zoneID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone: %w", err)
	}

	if err := json.Unmarshal(body, &zone); err != nil {
		return nil, fmt.Errorf("failed to parse zone response: %w", err)
	}

	return &zone, nil
}

// createZone creates a new DNS zone
func (c *netbirdProvider) createZone(req ZoneRequest) (*Zone, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal zone request: %w", err)
	}

	body, err := c.doRequest("POST", "/api/dns/zones", payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create zone: %w", err)
	}

	var zone Zone
	if err := json.Unmarshal(body, &zone); err != nil {
		return nil, fmt.Errorf("failed to parse zone response: %w", err)
	}

	return &zone, nil
}

// listRecords returns all DNS records in a zone
func (c *netbirdProvider) listRecords(zoneID string) ([]DNSRecord, error) {
	var records []DNSRecord
	body, err := c.doRequest("GET", fmt.Sprintf("/api/dns/zones/%s/records", zoneID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list records: %w", err)
	}

	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("failed to parse records response: %w", err)
	}

	return records, nil
}

// createRecord creates a new DNS record in a zone
func (c *netbirdProvider) createRecord(zoneID string, req DNSRecordRequest) (*DNSRecord, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal record request: %w", err)
	}

	body, err := c.doRequest("POST", fmt.Sprintf("/api/dns/zones/%s/records", zoneID), payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create record: %w", err)
	}

	var record DNSRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, fmt.Errorf("failed to parse record response: %w", err)
	}

	return &record, nil
}

// updateRecord updates an existing DNS record
func (c *netbirdProvider) updateRecord(zoneID, recordID string, req DNSRecordRequest) (*DNSRecord, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal record request: %w", err)
	}

	body, err := c.doRequest("PUT", fmt.Sprintf("/api/dns/zones/%s/records/%s", zoneID, recordID), payload)
	if err != nil {
		return nil, fmt.Errorf("failed to update record: %w", err)
	}

	var record DNSRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return nil, fmt.Errorf("failed to parse record response: %w", err)
	}

	return &record, nil
}

// deleteRecord deletes a DNS record from a zone
func (c *netbirdProvider) deleteRecord(zoneID, recordID string) error {
	_, err := c.doRequest("DELETE", fmt.Sprintf("/api/dns/zones/%s/records/%s", zoneID, recordID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete record: %w", err)
	}
	return nil
}

// doRequest performs an HTTP request to the Netbird API
func (c *netbirdProvider) doRequest(method, endpoint string, payload []byte) ([]byte, error) {
	url := c.apiBase + endpoint

	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Message != "" {
			return nil, errors.New(errResp.Message)
		}
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// newHTTPClient creates a new HTTP client with reasonable defaults
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
	}
}
