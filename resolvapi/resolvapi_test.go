package resolvapi

import (
	"testing"
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

}
