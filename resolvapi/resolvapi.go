package resolvapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

var (
	lokalResolverAddress = "127.0.0.1:5553" // preferably an instance of scion-sdns recursive resolver running locally
)

// ResolveUDPAddr parses the address and resolves the hostname.
// The address can be of the form of a SCION address (i.e. of the form "ISD-AS,[IP]:port")
// or in the form of "hostname:port".
// If the address is in the form of a hostname, the the following sources will
// be used to resolve a name, in the given order of precedence.
//
//   - /etc/hosts
//   - /etc/scion/hosts
//   - RAINS, if a server is configured in /etc/scion/rains.cfg. Disabled if built with !norains.
//   - DNS TXT records using the local DNS resolver (depending on OS config, see "Name Resolution" in net package docs)
//
// Returns HostNotFoundError if none of the sources did resolve the hostname.
func ResolveUDPAddr(ctx context.Context, address string) (pan.UDPAddr, error) {
	return resolveUDPAddrAt(ctx, address, defaultResolver())
}

//---------------------------------------------------------------------------------------------
/* resolves any queries using the local sdns resolver instance listening under 'lokalResolverAddress' */
type lokalDNSPrivacyResolver struct {
	//res dnsTXTResolver
}

/*type dnsPrivacyTXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}*/

var _ resolver = &lokalDNSPrivacyResolver{}

func (r *lokalDNSPrivacyResolver) LookupTXT(ctx context.Context, dname string) ([]string, error) {
	return LookupSCIONAddress(dname)
}

//const scionAddrTXTTag = "scion="

// Resolve the name via DNS to return one scionAddr or an error.
func (d *lokalDNSPrivacyResolver) Resolve(ctx context.Context, name string) (saddr pan.UDPAddr, err error) {
	addresses, err := d.queryTXTRecord(ctx, name)
	if err != nil {
		return pan.UDPAddr{}, err
	}
	var perr error
	for _, addr := range addresses {
		saddr, perr = pan.ParseUDPAddr(addr)
		if perr == nil {
			return saddr, nil
		}
	}
	return pan.UDPAddr{}, fmt.Errorf("error parsing TXT SCION address records: %w", perr)
}

// queryTXTRecord queries the DNS for DNS TXT record(s) specifying the SCION address(es) for host.
// Returns either at least one address, or else an error, of type HostNotFoundError if no matching record was found.
func (d *lokalDNSPrivacyResolver) queryTXTRecord(ctx context.Context, host string) (addresses []string, err error) {
	/*if d.res == nil {
		return addresses, fmt.Errorf("invalid DNS resolver: %v", d.res)
	}*/
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	txtRecords, err := d.LookupTXT(ctx, host)
	var errDNSError *net.DNSError
	if errors.As(err, &errDNSError) {
		if errDNSError.IsNotFound {
			return addresses, pan.HostNotFoundError{Host: host}
		}
	}
	if err != nil {
		return addresses, err
	}
	for _, txt := range txtRecords {
		if addr := dnsutil.SCIONAddrFromString(txt); addr != "" {
			addresses = append(addresses, addr)
		}
	}
	if len(addresses) == 0 {
		return addresses, pan.HostNotFoundError{Host: host}
	}
	return addresses, nil
}

//----------------------------------------------------------------------------------------

// inverse lookup
// ask local stub resolver 127.0.0.1:53  for the domain-name with this address
// makes no difference between IP and SCION Addresses both are threated as strings
func XLookupStub(address string) (string, error) {
	var query *dns.Msg = new(dns.Msg)
	invaddr, err := dnsutil.AddressToReverse(address)
	if err != nil {
		return "", err
	}
	query.SetQuestion(invaddr, dns.TypePTR)

	//response, err := dns.Exchange(query, resolverAddress) yielded 'dns: overflowing header size' somethimes because UDP buffer was only 512
	client := dns.Client{Net: "udp", UDPSize: 2048}
	response, _, err := client.Exchange(query, lokalResolverAddress)

	if err == nil {
		// parse response.Answer here
		//return response.Answer[0].String(), nil

		if len(response.Answer) > 0 { // maybe redundant, because implied by dns.RCodeSuccess
			var ans dns.RR = response.Answer[0] // how to handle more than one Answer here ?!
			a := ans.(*dns.PTR)
			if a != nil {
				return a.Ptr, nil
			} else {
				return "", nil
			}
		}

	}
	return "", err

}

/*lookup address using local sdns resolver running under 'lokalResolverAddress'*/
func LookupSCIONAddress(domain string) (answer []string, err error) {
	var query *dns.Msg = new(dns.Msg)

	query.SetQuestion(domain, dns.TypeTXT)

	//response, err := dns.Exchange(query, resolverAddress) yielded 'dns: overflowing header size' somethimes because UDP buffer was only 512
	client := dns.Client{Net: "udp", UDPSize: 2048, ReadTimeout: 99999999999}
	response, _, err := client.Exchange(query, lokalResolverAddress)

	if err == nil {
		// parse response.Answer here
		//return response.Answer[0].String(), nil

		if len(response.Answer) > 0 { // maybe redundant, because implied by dns.RCodeSuccess
			//var ans dns.RR = response.Answer[0]
			for _, ans := range response.Answer {
				if a, ok := ans.(*dns.A); ok {
					answer = append(answer, a.A.String())
				}

				if aaaa, ok := ans.(*dns.AAAA); ok {
					answer = append(answer, aaaa.AAAA.String())
				}
				if a, ok := ans.(*dns.TXT); ok {
					answer = append(answer, strings.Join(a.Txt, ""))
				}
			}
		}

	}
	return answer, err

}
