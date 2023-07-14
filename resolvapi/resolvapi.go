package resolvapi

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
)

var (
	resolverAddress = "127.0.0.1:5553" // preferably an instance of scion-sdns recursive resolver running locally
)

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
	response, _, err := client.Exchange(query, resolverAddress)

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

func LookupSCIONAddress(domain string) (answer []string, err error) {
	var query *dns.Msg = new(dns.Msg)
	/*query.Question = []dns.Question{{Name: domain, Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: domain, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		{Name: domain, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
		query.RecursionDesired = true
	}*/

	query.SetQuestion(domain, dns.TypeTXT)

	//response, err := dns.Exchange(query, resolverAddress) yielded 'dns: overflowing header size' somethimes because UDP buffer was only 512
	client := dns.Client{Net: "udp", UDPSize: 2048, ReadTimeout: 99999999999}
	response, _, err := client.Exchange(query, resolverAddress)

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
