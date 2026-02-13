// Package libdnstemplate implements a DNS record management client compatible
// with the libdns interfaces for <PROVIDER NAME>. TODO: This package is a
// template only. Customize all godocs for actual implementation.
package ldnsupd

import (
	"context"
	"sync"

	"github.com/libdns/libdns"
)

// Providers must not require additional provisioning steps by the callers; it
// should work simply by populating a struct and calling methods on it. If your DNS
// service requires long-lived state or some extra provisioning step, do it implicitly
// when methods are called; sync.Once can help with this, and/or you can use a
// sync.(RW)Mutex in your Provider struct to synchronize implicit provisioning.

// Provider facilitates DNS record manipulation with cdydnsupd
type Provider struct {
	TSIGKeyName string `json:"tsig_key_name,omitempty"`
	TSIGSecret string `json:"tsig_secret,omitempty"`
	TSIGAlgorithm string `json:"tsig_algorithm,omitempty"`
	DNSServer string `json:"dns_server,omitempty"`
	mutex sync.Mutex
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Make sure to return RR-type-specific structs, not libdns.RR structs.
	var appendedRecords []libdns.Record

	for _, rec := range records {
		err := p.updateRecord(ctx, zone, rec, false)
		if err != nil {
			return nil, err
		}
		appendedRecords = append(appendedRecords, rec)
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var setRecords []libdns.Record

	for _, rec := range records {
		err := p.updateRecord(ctx, zone, rec, false)
		if err != nil {
			return nil, err
		}
		setRecords = append(setRecords, rec)
	}

	return setRecords, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record

	for _, rec := range records {
		err := p.updateRecord(ctx, zone, rec, true)
		if err != nil {
			return nil, err
		}
		deletedRecords = append(deletedRecords, rec)
	}

	return deletedRecords, nil
}

// Interface guards
var (
	// _ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
