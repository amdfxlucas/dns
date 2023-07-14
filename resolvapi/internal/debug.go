package main

import (
	"fmt"

	"github.com/miekg/dns/resolvapi"
)

func testXLookup() {
	tests := []struct {
		address string
		domain  string
	}{
		{"19-ffaa:1:1067,10.0.2.15", "ns2.scion.test."},
		{"19-ffaa:1:1094,[127.0.0.1]", "scnd2.scion.test."},
		{"19-ffaa:1:fe4,127.0.0.1", "rhine.ovgu.scionlab."},
	}

	for _, d := range tests {
		if name, err := resolvapi.XLookupStub(d.address); err == nil {
			if name != d.domain {
				fmt.Printf("Error rDNS lookup of: %v got domain name: %v\n", d.address, name)
			} else {
				fmt.Printf("rDNS lookup successful: %v %v\n", d.address, d.domain)
			}

		} else {
			fmt.Printf("Error rDNS lookup of: %v Got error: %v \n", d.address, err)
		}
	}
}

func main() {

	//	testXLookup()

	if addresses, err := resolvapi.LookupSCIONAddress("dummy.scion.test."); err == nil {
		fmt.Print(addresses)
	} else {
		fmt.Print(err.Error())
	}

}
