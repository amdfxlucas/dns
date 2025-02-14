// Copyright 2022 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resolvapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns/dnsutil"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

type dnsResolver struct {
	res dnsTXTResolver
}

type dnsTXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupAddr(context.Context, string) ([]string, error) // reverse lookup of domain names corresponding to an address
}

var _ resolver = &dnsResolver{}

const scionAddrTXTTag = "scion="

/*
	lookup domain names for address

\param reverseAddress can be a reverse scion address like 1.0.0.127.in-addr.19-ffaa-1-fe4.scion.arpa.
or a normal scion address like 17-ffaa:0:1,[192.168.1.1]
*/
func (d *dnsResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	// return d.res.LookupAddr(ctx, addr)
	// only a stub, this wont work as netresolver does not know howto reverse scion addr
	// if net.Resolver only had a public LookupPTR() method :(

	return nil, errors.New("NotImplemented")
}

// Resolve the name via DNS to return one scionAddr or an error.
func (d *dnsResolver) Resolve(ctx context.Context, name string) (saddr pan.UDPAddr, err error) {
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
func (d *dnsResolver) queryTXTRecord(ctx context.Context, host string) (addresses []string, err error) {
	if d.res == nil {
		return addresses, fmt.Errorf("invalid DNS resolver: %v", d.res)
	}
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	txtRecords, err := d.res.LookupTXT(ctx, host)
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
		/*if strings.HasPrefix(txt, scionAddrTXTTag) {
			addresses = append(addresses, strings.TrimPrefix(txt, scionAddrTXTTag))
		}*/
		if addr := dnsutil.SCIONAddrFromString(txt); addr != "" {
			addresses = append(addresses, addr)
		}
	}
	if len(addresses) == 0 {
		return addresses, pan.HostNotFoundError{Host: host}
	}
	return addresses, nil
}
