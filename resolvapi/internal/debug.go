package main

import (
	"context"
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

func TestResolveUDPAddr() {

	tests := []struct {
		domain  string
		address string
	}{

		{"dummy.scion.test.:53", "19-ffaa:1:1067,[127.0.0.2]"},
		{"example.scion.test.:53", "19-ffaa:1:1067,[127.0.0.3]"},
		{"netsec.ethz.ch.:443", "17-ffaa:0:1102,[129.132.121.164]"},
	}

	for _, d := range tests {
		if ad, er := resolvapi.ResolveUDPAddr(context.Background(), d.domain); er == nil {
			fmt.Println(ad)
		} else {
			fmt.Println(er)
		}

	}
}

func main() {

	//	testXLookup()

	/*if addresses, err := resolvapi.LookupSCIONAddress("dummy.scion.test."); err == nil {
		fmt.Print(addresses)
	} else {
		fmt.Print(err.Error())
	}
	*/

	TestResolveUDPAddr()

}
