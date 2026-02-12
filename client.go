package ldnsupd

import (
	"context"
	"fmt"
	// "io"
	"net"
	// "net/http"
	"net/netip"
	// "net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

func (p *Provider) getDomain(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var libRecords []libdns.Record

	// we trim the dot at the end of the zone name to get the fqdn
	fqdn := strings.TrimRight(zone, ".")

	resolver := defaultResolver
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, resolver)
		},
	}
	ips, err := r.LookupHost(ctx, fqdn)
	if err != nil {
		return libRecords, fmt.Errorf("libdnsexecupdater unable to lookup host: %w", err)
	}

	for _, ip := range ips {
		parsedIp, err := netip.ParseAddr(ip)
		if err != nil {
			return libRecords, fmt.Errorf("libdnsexecupdater unable to parse IP address '%s': %w", ip, err)
		}
		libRecords = append(libRecords, libdns.Address{
			Name: "@",
			IP:   parsedIp,
		})
	}

	txt, err := r.LookupTXT(ctx, fqdn)
	if err != nil {
		return libRecords, fmt.Errorf("libdnsexecupdater unable to lookup TXT records for '%s': %w", fqdn, err)
	}
	for _, t := range txt {
		if t == "" {
			continue
		}
		libRecords = append(libRecords, libdns.TXT{
			Name: "@",
			Text: t,
		})
	}

	return libRecords, nil
}

func (p *Provider) updateRecord(ctx context.Context, zone string, record libdns.Record, clear bool) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	rr, err := record.RR().Parse()
	if err != nil {
		return fmt.Errorf("libdnsexecupdater unable to parse libdns.RR: %w", err)
	}

	// sanitize the domain, combines the zone and record names
	// the record name should typically be relative to the zone
	//domain := libdns.AbsoluteName(record.RR().Name, zone)

	// DNS server and zone details
	server := p.DNSServer + ":53"
	// zone := domain
	// ttl := 3600

	name := ""
	value := ""
	switch rec := rr.(type) {
	case libdns.TXT:
		name = record.RR().Name
		value = rec.Text
	default:
		return fmt.Errorf("libdnsexecupdater unsupported record type: %s", record.RR().Type)
	}

	// TSIG key details (replace with your actual key)
	keyName := p.TSIGKeyName
	algorithm := dns.HmacSHA256
	// key := []byte(p.TSIGSecret)

	// Create a new DNS client
	c := new(dns.Client)
	c.TsigSecret = map[string]string{ keyName: p.TSIGSecret }

	// Create a new UPDATE message
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.SetTsig(keyName, algorithm, 300, int64(time.Now().Unix()))

	// Add the TXT record to update
	newrr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Txt: []string{value},
	}

	if clear {
		m.Remove([]dns.RR{newrr})
	} else {
		m.Insert([]dns.RR{newrr})
	}

	// Send the update request
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		fmt.Println("Failed to send update: %v", err)
	}

	// Check response
	if resp.Rcode != dns.RcodeSuccess {
		fmt.Println("Update failed: %s", dns.RcodeToString[resp.Rcode])
	}

	fmt.Println("TXT record updated successfully")

	// make the request to duckdns to set the records according to the params
	// _, err = p.doRequest(ctx, domain, params)
	// if err != nil {
	// 	return err
	// }
	return nil
}

// func (p *Provider) doRequest(ctx context.Context, domain string, params map[string]string) ([]string, error) {
// 	u, _ := url.Parse(duckDNSUpdateURL)

// 	// extract the main domain
// 	var mainDomain string
// 	if p.OverrideDomain != "" {
// 		mainDomain = p.OverrideDomain
// 	} else {
// 		mainDomain = getMainDomain(domain)
// 	}

// 	if len(mainDomain) == 0 {
// 		return nil, fmt.Errorf("libdnsexecupdater unable to find the main domain for: %s", domain)
// 	}

// 	if len(p.APIToken) != 36 {
// 		return nil, fmt.Errorf("libdnsexecupdater API token must be a 36 characters long UUID, got: '%s'", p.APIToken)
// 	}

// 	// set up the query with the params we always set
// 	query := u.Query()
// 	query.Set("domains", mainDomain)
// 	query.Set("token", p.APIToken)

// 	// add the remaining ones for this request
// 	for key, val := range params {
// 		query.Set(key, val)
// 	}

// 	// set the query back on the URL
// 	u.RawQuery = query.Encode()

// 	// make the request
// 	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("libdnsexecupdater unable to create request: %w", err)
// 	}

// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("libdnsexecupdater unable to make request: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	bodyBytes, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, fmt.Errorf("libdnsexecupdater unable to read response body: %w", err)
// 	}

// 	body := string(bodyBytes)
// 	bodyParts := strings.Split(body, "\n")
// 	if bodyParts[0] != responseOK {
// 		return nil, fmt.Errorf("libdnsexecupdater request failed, expected (OK) but got (%s), url: [%s], body: %s", bodyParts[0], u.String(), body)
// 	}

// 	return bodyParts, nil
// }

func getMainDomain(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	split := dns.Split(domain)
	if strings.HasSuffix(strings.ToLower(domain), MyDNSDomain) {
		if len(split) < 2 {
			return ""
		}

		firstSubDomainIndex := split[len(split)-2]
		return domain[firstSubDomainIndex:]
	}

	return domain[split[len(split)-1]:]
}

const (
	MyDNSDomain    = "layer-7.net"
	responseOK       = "OK"
	defaultResolver  = "8.8.8.8:53" // Google's public DNS server
)
