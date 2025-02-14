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
	"context"
	"fmt"
	"testing"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

const hostsTestFile = "hosts_test_file"

func TestCount(t *testing.T) {
	hosts, err := loadHostsFile(hostsTestFile)
	if err != nil {
		t.Fatal("error loading test file", err)
	}

	assert.Equal(t, 5, len(hosts.addresses), "wrong number of hosts read from hosts_test_file")
}

func TestHostsfileResolver(t *testing.T) {
	resolver := &hostsfileResolver{hostsTestFile}

	cases := []struct {
		name      string
		assertErr assert.ErrorAssertionFunc
		expected  pan.UDPAddr
	}{
		{"host1.1", assert.NoError, mustParse("17-ffaa:0:1,[192.168.1.1]")},
		{"host1.2", assert.NoError, mustParse("17-ffaa:0:1,[192.168.1.1]")},
		{"host2", assert.NoError, mustParse("18-ffaa:1:2,[10.0.8.10]")},
		{"host3", assert.NoError, mustParse("17-ffaa:0:1,[192.168.1.1]")},
		{"host4", assert.NoError, mustParse("20-ffaa:c0ff:ee12,[::ff1:ce00:dead:10cc:baad:f00d]")},
		{"commented", assertErrHostNotFound, pan.UDPAddr{}},
		{"dummy1", assertErrHostNotFound, pan.UDPAddr{}},
		{"dummy2", assertErrHostNotFound, pan.UDPAddr{}},
		{"dummy3", assertErrHostNotFound, pan.UDPAddr{}},
		{"foobar", assertErrHostNotFound, pan.UDPAddr{}},
	}
	for _, c := range cases {
		actual, err := resolver.Resolve(context.TODO(), c.name)
		if !c.assertErr(t, err) {
			continue
		}
		assert.Equal(t, c.expected, actual)
	}

}

func TestHostfileResolverReverse(t *testing.T) {
	resolver := &hostsfileResolver{hostsTestFile}
	revcases := []struct {
		address   string
		assertErr assert.ErrorAssertionFunc
		expected  []string
	}{

		{"1.0.0.127.in-addr.19-ffaa-1-fe4.scion.arpa.", assert.NoError, []string{"rhine.ovgu.scionlab."}},
		{"111.7.44.141.in-addr.arpa.", assert.NoError, []string{"www.ovgu.de"}},
		{"115.7.44.141.in-addr.arpa.", assert.NoError, []string{"www.fin.ovgu.de", "www2.cs.ovgu.de"}},
	}
	for _, c := range revcases {
		actual, err := resolver.LookupAddr(context.TODO(), c.address)
		if !c.assertErr(t, err) {
			continue
		}
		assert.Equal(t, c.expected, actual)
	}
}

func TestHostsfileResolverNonexisting(t *testing.T) {
	resolver := &hostsfileResolver{"non_existing_hosts_file"}
	_, err := resolver.Resolve(context.TODO(), "something")
	assert.Error(t, err)
}

func TestResolverList(t *testing.T) {
	primary := map[string]pan.UDPAddr{
		"foo": mustParse("1-ff00:0:f00,[192.0.2.1]"),
		"bar": mustParse("1-ff00:0:ba3,[192.0.2.1]"),
	}
	secondary := map[string]pan.UDPAddr{
		"bar": mustParse("1-ff00:0:ba3,[2001:db8:ffff:ffff:ffff:ffff:baad:f00d]"), // shadowed by bar in primary
		"baz": mustParse("1-ff00:0:ba5,[192.0.2.1]"),
	}
	resolver := resolverList{
		dummyResolver{primary},
		dummyResolver{secondary},
	}

	cases := []struct {
		name      string
		assertErr assert.ErrorAssertionFunc
		expected  pan.UDPAddr
	}{
		{"foo", assert.NoError, mustParse("1-ff00:0:f00,[192.0.2.1]")},
		{"bar", assert.NoError, mustParse("1-ff00:0:ba3,[192.0.2.1]")},
		{"baz", assert.NoError, mustParse("1-ff00:0:ba5,[192.0.2.1]")},
		{"boo", assertErrHostNotFound, pan.UDPAddr{}},
	}
	for _, c := range cases {
		actual, err := resolver.Resolve(context.TODO(), c.name)
		c.assertErr(t, err)
		assert.Equal(t, c.expected, actual)
	}
}

func assertErrHostNotFound(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
	target := pan.HostNotFoundError{}
	return assert.ErrorAs(t, err, &target, msgAndArgs...)
}

type dummyResolver struct {
	hosts map[string]pan.UDPAddr
}

var _ resolver = &dummyResolver{}

func (r dummyResolver) LookupAddr(ctx context.Context, address string) ([]string, error) {
	return nil, nil
}

func (r dummyResolver) Resolve(ctx context.Context, name string) (pan.UDPAddr, error) {
	if h, ok := r.hosts[name]; ok {
		return h, nil
	} else {
		return pan.UDPAddr{}, pan.HostNotFoundError{Host: name}
	}
}

func mustParse(address string) pan.UDPAddr {
	a, err := pan.ParseUDPAddr(address)
	if err != nil {
		panic(fmt.Sprintf("test input must parse %s", err))
	}
	return a
}

func TestParseSCIONAddr(t *testing.T) {
	cases := []struct {
		input     string
		assertErr assert.ErrorAssertionFunc
		expected  pan.UDPAddr
	}{
		{
			input:     "1-ff00:0:0,[1.1.1.1]",
			assertErr: assert.NoError,
			expected:  pan.UDPAddr{IA: pan.MustParseIA("1-ff00:0:0"), IP: netaddr.MustParseIP("1.1.1.1")},
		},
		{
			input:     "1-ff00:0:0,1.1.1.1",
			assertErr: assert.NoError,
			expected:  pan.UDPAddr{IA: pan.MustParseIA("1-ff00:0:0"), IP: netaddr.MustParseIP("1.1.1.1")},
		},
		{
			input:     "1-ff00:0:0,[::]",
			assertErr: assert.NoError,
			expected:  pan.UDPAddr{IA: pan.MustParseIA("1-ff00:0:0"), IP: netaddr.MustParseIP("::")},
		},
		{
			input:     "1-ff00:0:0,::",
			assertErr: assert.NoError,
			expected:  pan.UDPAddr{IA: pan.MustParseIA("1-ff00:0:0"), IP: netaddr.MustParseIP("::")},
		},
		{input: "1-ff00:0:0,[[::]]", assertErr: assert.Error},
		{input: "1-ff00:0:0,::]", assertErr: assert.Error},
		{input: "1-ff00:0:0,[::", assertErr: assert.Error},
	}
	for _, c := range cases {
		actual, err := pan.ParseUDPAddr(c.input)
		if !c.assertErr(t, err, "input '%s' %s", c.input) {
			continue
		}
		assert.Equal(t, c.expected, actual, "bad result for input '%s'", c.input)
	}

}

func TestSplitHostPort(t *testing.T) {
	type testCase struct {
		input     string
		assertErr assert.ErrorAssertionFunc
		host      string
		port      string
	}
	cases := []testCase{
		{"1-ff00:0:0,[1.1.1.1]:80", assert.NoError, "1-ff00:0:0,[1.1.1.1]", "80"},
		{"1-ff00:0:0,1.1.1.1:80", assert.NoError, "1-ff00:0:0,1.1.1.1", "80"},
		{"1-ff00:0:0,[::]:80", assert.NoError, "1-ff00:0:0,[::]", "80"},
		{"foo:80", assert.NoError, "foo", "80"},
		{"www.example.com:666", assert.NoError, "www.example.com", "666"},
		{"1-ff00:0:0,0:0:0:80", assert.Error, "", ""},
		{":foo:666", assert.Error, "", ""},
		{"1-ff00:0:0,[1.1.1.1]", assert.Error, "", ""},
		{"1-ff00:0:0,1.1.1.1", assert.Error, "", ""},
		{"1-ff00:0:0,[::]", assert.Error, "", ""},
		{"foo", assert.Error, "", ""},
	}
	for _, c := range cases {
		host, port, err := pan.SplitHostPort(c.input)
		if !c.assertErr(t, err) {
			continue
		}
		assert.Equal(t, c.host, host, "bad host for input '%s'", c.input)
		assert.Equal(t, c.port, port, "bad port for input '%s'", c.input)
	}
}
