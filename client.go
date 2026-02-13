package ldnsupd

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

func (p *Provider) updateRecord(ctx context.Context, zone string, record libdns.Record, delete bool) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var name string
	var value string
	rec, err := record.RR().Parse()
	if err != nil {
		return fmt.Errorf("ldnsupd unable to parse libdns.RR: %w", err)
	}
	switch parsed := rec.(type) {
	case libdns.TXT:
		name = parsed.Name
		value = parsed.Text
	default:
		return fmt.Errorf("ldnsupd unsupported record type: %s", record.RR().Type)
	}

	// sanitize the domain, combines the zone and record names
	// the record name should typically be relative to the zone
	domain := libdns.AbsoluteName(name, zone)

	// fmt.Printf("name is %s\n", name)
	// fmt.Printf("zone is %s\n", zone)
	// fmt.Printf("domain is %s\n", domain)
	// fmt.Printf("value is %s\n", value)
	// fmt.Printf("algorithm is %s\n", dns.Fqdn(p.TSIGAlgorithm))

	// Create a new DNS client
	c := new(dns.Client)
	c.TsigSecret = map[string]string{ dns.Fqdn(p.TSIGKeyName): p.TSIGSecret }

	// Create a new UPDATE message
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.SetTsig(dns.Fqdn(p.TSIGKeyName), dns.Fqdn(p.TSIGAlgorithm), 300, int64(time.Now().Unix()))

	// Add the TXT record to update
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Txt: []string{value},
	}

	if delete {
		m.Remove([]dns.RR{rr})
	} else {
		m.Insert([]dns.RR{rr})
	}
	// fmt.Printf("message: \n%+v\n", m)

	resp, _, err := c.Exchange(m, p.DNSServer)
	if err != nil {
		return fmt.Errorf("ldnsupd failed to send update: %v\n", err)
	}

	// Check response
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("ldnsupd update failed: %s\n", dns.RcodeToString[resp.Rcode])
	}

	return nil
}

const (
	defaultResolver  = "8.8.8.8:53" // Google's public DNS server
)
