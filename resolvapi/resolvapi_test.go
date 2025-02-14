package resolvapi

import (
	"testing"

	"golang.org/x/exp/slices"
)

/*
first get rid of system-resolver
systemctl stop [systemd-resolved.service](https://systemd.network/systemd-resolved.service.html)

then start scion-sdns locally and configure it to:
  - bind on 127.0.0.1:53 (udp -downstream )
  - forward to at least one scion-root server i.e. 19-ffaa:1:1067:853 (make sure its actually running) (squic doq upstream)

then you should be able to query any entry from the reverse .scion.arpa. zone here in this test
*/
func TestXLookup(t *testing.T) {

	tests := []struct {
		address string
		domains []string
	}{
		{"19-ffaa:1:1067,10.0.2.15", []string{"ns2.scion.test"}},
		{"19-ffaa:1:1094,[127.0.0.1]", []string{"scnd2.scion.test"}},
		// 17-ffaa:1:1008,127.0.0.1, ethz.something ?!
		{"19-ffaa:1:fe4,127.0.0.1", []string{"rhine.ovgu.scionlab."}},
	}

	for _, d := range tests {
		if names, err := XLookupStub(d.address); err == nil {

			for _, dname := range d.domains {

				if !slices.Contains(names, dname) {
					t.Errorf("Error rDNS lookup of: %v didnt get domain name: %v\n", d.address, dname)
				}
			}
			/*} else {
				t.Errorf("Error rDNS lookup of: %v Got error: %v \n", d.address, err)
			}*/
		}
	}

}
