package resolvapi

import (
	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
)

var (
	resolverAddress = "127.0.0.1" // preferably an instance of scion-sdns recursive resolver running locally
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

	response, err := dns.Exchange(query, resolverAddress)

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
