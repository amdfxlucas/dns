// Copyright 2018 ETH Zurich
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
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	util "github.com/miekg/dns/dnsutil"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

type hostsTable struct {
	addresses    map[string]pan.UDPAddr
	revAddresses map[string][]string
}

// hostsfileResolver is an implementation of the resolver interface, backed
// by an /etc/hosts-like file.
type hostsfileResolver struct {
	path string
}

/*
	lookup domain names for address

\param reverseAddress can be a reverse scion address like 1.0.0.127.in-addr.19-ffaa-1-fe4.scion.arpa.
or a normal scion address like 17-ffaa:0:1,[192.168.1.1]
*/
func (r *hostsfileResolver) LookupAddr(ctx context.Context, reverseAddress string) ([]string, error) {
	var e error
	if val := util.IsReverse(reverseAddress); val == 0 {
		reverseAddress, e = util.ReverseSCIONAddr(reverseAddress)
		if e != nil {
			return nil, errors.New("address was neither reverse nor normal scion address")
		}
	}

	table, err := loadHostsFile(r.path)

	if err != nil {
		return nil, fmt.Errorf("error loading %s: %w", r.path, err)
	}

	dname, ok := table.revAddresses[reverseAddress]
	if !ok {
		return nil, pan.HostNotFoundError{reverseAddress}
	}
	return dname, nil

}

func (r *hostsfileResolver) ResolveReverse(ctx context.Context, addr pan.UDPAddr) ([]string, error) {
	table, err := loadHostsFile(r.path)

	if err != nil {
		return nil, fmt.Errorf("error loading %s: %w", r.path, err)
	}

	rev, e := util.ReverseSCIONAddr(addr.String())
	if e != nil {
		return nil, fmt.Errorf("error while reversing address: %v\n", addr.String())
	}

	dname, ok := table.revAddresses[rev]
	if !ok {
		return nil, pan.HostNotFoundError{rev}
	}
	return dname, nil
}

func (r *hostsfileResolver) Resolve(ctx context.Context, name string) (pan.UDPAddr, error) {
	// Note: obviously not perfectly elegant to parse the entire file for
	// every query. However, properly caching this and still always provide
	// fresh results after changes to the hosts file seems like a bigger task and
	// for now that would be overkill.
	table, err := loadHostsFile(r.path)
	if err != nil {
		return pan.UDPAddr{}, fmt.Errorf("error loading %s: %w", r.path, err)
	}
	addr, ok := table.addresses[name]
	if !ok {
		return pan.UDPAddr{}, pan.HostNotFoundError{name}
	}
	return addr, nil
}

func loadHostsFile(path string) (hostsTable, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		// not existing file treated like an empty file,
		// just return an empty table
		return hostsTable{}, nil
	} else if err != nil {
		return hostsTable{}, err
	}
	defer file.Close()
	return parseHostsFile(file)
}

func parseHostsFile(file *os.File) (hostsTable, error) {
	var table hostsTable
	table.addresses = make(map[string]pan.UDPAddr)
	table.revAddresses = make(map[string][]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// ignore comments
		cstart := strings.IndexRune(line, '#')
		if cstart >= 0 {
			line = line[:cstart]
		}

		// cut into fields: address name1 name2 ...
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		addr, err := pan.ParseUDPAddr(fields[0])
		if err != nil {
			if val := util.IsReverse(fields[0]); val != 0 {

				switch val {
				case 3:
					unReversedAddr := util.ExtractAddressFromReverse(fields[0])
					//unReversedAddr := util.UnReverseSCION(fields[0])
					_, e := pan.ParseUDPAddr(unReversedAddr)
					if e == nil {

						hostnames := table.revAddresses[fields[0]]
						for _, name := range fields[1:] {
							hostnames = append(hostnames, name)
						}
						table.revAddresses[fields[0]] = hostnames
					}
				case 1, 2:
					hostnames := table.revAddresses[fields[0]]
					for _, name := range fields[1:] {
						hostnames = append(hostnames, name)
					}
					table.revAddresses[fields[0]] = hostnames
				}

				continue

			} else {
				// if its neither an address nor a PTR RR (reverse address)  it must be garbage
				continue
			}

		}

		// map hostnames to scionAddress
		for _, name := range fields[1:] {
			table.addresses[name] = addr
		}
	}
	return table, scanner.Err()
}
