package dns

// A client implementation.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"
	"inet.af/netaddr"
)

const (
	dnsTimeout     time.Duration = 2 * time.Second
	tcpIdleTimeout time.Duration = 8 * time.Second
)

func isPacketConn(c net.Conn) bool {
	if _, ok := c.(net.PacketConn); !ok {
		return false
	}

	if ua, ok := c.LocalAddr().(*net.UnixAddr); ok {
		return ua.Net == "unixgram" || ua.Net == "unixpacket"
	}

	return true
}

// A Conn represents a connection to a DNS server.
type Conn struct {
	net.Conn                         // a net.Conn holding the connection
	UDPSize        uint16            // minimum receive buffer for UDP messages
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2)
	TsigProvider   TsigProvider      // An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
	tsigRequestMAC string

	QuicEarlySession *pan.QUICEarlySession
	//quicSession      *pan.QUICSession
	qstream *quic.Stream
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.Conn == nil {
		if c.qstream != nil {
			return (*c.qstream).SetReadDeadline(t)
		} else {
			return nil
		}
	} else {
		return c.Conn.SetReadDeadline(t)
	}
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.Conn == nil {
		if c.qstream != nil {
			return (*c.qstream).SetWriteDeadline(t)
		} else {
			return nil
		}
	} else {
		return c.Conn.SetWriteDeadline(t)
	}
}

func (c *Conn) Close() error {
	if c.Conn == nil {
		return nil
	} else {
		return c.Conn.Close()
	}

}

func (co *Conn) tsigProvider() TsigProvider {
	if co.TsigProvider != nil {
		return co.TsigProvider
	}
	// tsigSecretProvider will return ErrSecret if co.TsigSecret is nil.
	return tsigSecretProvider(co.TsigSecret)
}

// A Client defines parameters for a DNS client.
type Client struct {
	Net       string      // if "tcp" or "tcp-tls" (DNS over TLS) a TCP query will be initiated, otherwise an UDP one (default is "" for UDP)
	UDPSize   uint16      // minimum receive buffer for UDP messages
	TLSConfig *tls.Config // TLS connection configuration
	Dialer    *net.Dialer // a net.Dialer used to set local address, timeouts and more
	// Timeout is a cumulative timeout for dial, write and read, defaults to 0 (disabled) - overrides DialTimeout, ReadTimeout,
	// WriteTimeout when non-zero. Can be overridden with net.Dialer.Timeout (see Client.ExchangeWithDialer and
	// Client.Dialer) or context.Context.Deadline (see ExchangeContext)
	Timeout        time.Duration
	DialTimeout    time.Duration     // net.DialTimeout, defaults to 2 seconds, or net.Dialer.Timeout if expiring earlier - overridden by Timeout when that value is non-zero
	ReadTimeout    time.Duration     // net.Conn.SetReadTimeout value for connections, defaults to 2 seconds - overridden by Timeout when that value is non-zero
	WriteTimeout   time.Duration     // net.Conn.SetWriteTimeout value for connections, defaults to 2 seconds - overridden by Timeout when that value is non-zero
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2)
	TsigProvider   TsigProvider      // An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
	SingleInflight bool              // if true suppress multiple outstanding queries for the same Qname, Qtype and Qclass
	group          singleflight
}

// Exchange performs a synchronous UDP query. It sends the message m to the address
// contained in a and waits for a reply. Exchange does not retry a failed query, nor
// will it fall back to TCP in case of truncation.
// See client.Exchange for more information on setting larger buffer sizes.
func Exchange(m *Msg, a string) (r *Msg, err error) {
	client := Client{Net: "udp"}
	r, _, err = client.Exchange(m, a)
	return r, err
}

func ExchangeClient(c *Client, m *Msg, a string) (r *Msg, err error) {

	r, _, err = c.Exchange(m, a)
	return r, err
}

func (c *Client) dialTimeout() time.Duration {
	if c.Timeout != 0 {
		return c.Timeout
	}
	if c.DialTimeout != 0 {
		return c.DialTimeout
	}
	return dnsTimeout
}

func (c *Client) readTimeout() time.Duration {
	if c.ReadTimeout != 0 {
		return c.ReadTimeout
	}
	return dnsTimeout
}

func (c *Client) writeTimeout() time.Duration {
	if c.WriteTimeout != 0 {
		return c.WriteTimeout
	}
	return dnsTimeout
}

// Dial connects to the address on the named network.
func (c *Client) Dial(address string) (conn *Conn, err error) {
	return c.DialContext(context.Background(), address)
}

// DialContext connects to the address on the named network, with a context.Context.
// For TLS over TCP (DoT) the context isn't used yet. This will be enabled when Go 1.18 is released.
func (c *Client) DialContext(ctx context.Context, address string) (conn *Conn, err error) {
	// create a new dialer with the appropriate timeout
	var d net.Dialer
	var useTLS bool = false

	conn = new(Conn)
	network := c.Net
	if network == "squic" {
		var local netaddr.IPPort

		/*		if len := len(r.cfg.OutboundIPs); len > 0 {
				// loop until we have at least one suitable outboundIP address
				for i := 0; i < len; i++ {
					var outAddr string = r.cfg.OutboundIPs[i]
					local, err = netaddr.ParseIPPort(outAddr)
					if err != nil {
						fmt.Printf("invalid outboundIPv4 address: %v \n", outAddr)
					} else {
						fmt.Printf("outip: %v\n", outAddr)
						// exit loop, we have what we need
						break
					}
				}
			}*/

		var hostForSNI string = "localhost" // hacky shortcut, because i know what domain-name my server's certificate is issued on ( that is 'localhost' amongst others)
		// this has to be the domain name of the nameserver we are about to dial
		// It is required for the crypto handshake to succeed.
		// For production, we have to look this up with 'Reverse DNS Lookup (rDNS)' of the servers ('remote') IP address through one of the other bootstrap/root-servers
		// TODO: create Method func hostSNIFromAddr( serverAddrToReverseLookup string, cfg *config.Config ) ( serverSNIToAddress string, error)
		// NOTE: adguardteam/dnsproxy uses the Host portion of the remote address for this

		var remote pan.UDPAddr
		remote, err = pan.ParseUDPAddr(address)
		if err != nil {
			fmt.Printf("parse of pan.UPDAddr failed with: %v in dns.Client \n", address)
		}
		dialCtx, cancel := context.WithTimeout(ctx, c.getTimeoutForRequest(c.dialTimeout()))
		defer cancel()
		conn.QuicEarlySession, err = pan.DialQUICEarly(dialCtx, local, remote, nil, nil, hostForSNI, c.TLSConfig, &quic.Config{MaxIdleTimeout: 5 * time.Minute})

		if err != nil {
			fmt.Printf("dialQUIC failed in dns.Client: %v \n", err.Error())
		}
		goto finished
	} else if network == "" {
		network = "udp"
	}
	if c.Dialer == nil {
		d = net.Dialer{Timeout: c.getTimeoutForRequest(c.dialTimeout())}
	} else {
		d = *c.Dialer
	}

	useTLS = strings.HasPrefix(network, "tcp") && strings.HasSuffix(network, "-tls")

	if useTLS {
		network = strings.TrimSuffix(network, "-tls")

		// TODO(miekg): Enable after Go 1.18 is released, to be able to support two prev. releases.
		/*
			tlsDialer := tls.Dialer{
				NetDialer: &d,
				Config:    c.TLSConfig,
			}
			conn.Conn, err = tlsDialer.DialContext(ctx, network, address)
		*/
		conn.Conn, err = tls.DialWithDialer(&d, network, address, c.TLSConfig)
	} else {
		conn.Conn, err = d.DialContext(ctx, network, address)
	}
finished:
	if err != nil {
		return nil, err
	}
	conn.UDPSize = c.UDPSize
	return conn, nil
}

// Exchange performs a synchronous query. It sends the message m to the address
// contained in a and waits for a reply. Basic use pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	in, rtt, err := c.Exchange(message, "127.0.0.1:53")
//
// Exchange does not retry a failed query, nor will it fall back to TCP in
// case of truncation.
// It is up to the caller to create a message that allows for larger responses to be
// returned. Specifically this means adding an EDNS0 OPT RR that will advertise a larger
// buffer, see SetEdns0. Messages without an OPT RR will fallback to the historic limit
// of 512 bytes
// To specify a local address or a timeout, the caller has to set the `Client.Dialer`
// attribute appropriately
func (c *Client) Exchange(m *Msg, address string) (r *Msg, rtt time.Duration, err error) {
	co, err := c.Dial(address)

	if err != nil {
		return nil, 0, err
	}
	if c.Net != "squic" {
		defer co.Close()
	}

	return c.ExchangeWithConn(m, co)
}

// ExchangeWithConn has the same behavior as Exchange, just with a predetermined connection
// that will be used instead of creating a new one.
// Usage pattern with a *dns.Client:
//
//	c := new(dns.Client)
//	// connection management logic goes here
//
//	conn := c.Dial(address)
//	in, rtt, err := c.ExchangeWithConn(message, conn)
//
// This allows users of the library to implement their own connection management,
// as opposed to Exchange, which will always use new connections and incur the added overhead
// that entails when using "tcp" and especially "tcp-tls" clients.
//
// When the singleflight is set for this client the context is _not_ forwarded to the (shared) exchange, to
// prevent one cancelation from canceling all outstanding requests.
func (c *Client) ExchangeWithConn(m *Msg, conn *Conn) (r *Msg, rtt time.Duration, err error) {
	return c.exchangeWithConnContext(context.Background(), m, conn)
}

func (c *Client) exchangeWithConnContext(ctx context.Context, m *Msg, conn *Conn) (r *Msg, rtt time.Duration, err error) {
	if !c.SingleInflight {
		return c.exchangeContext(ctx, m, conn)
	}

	q := m.Question[0]
	key := fmt.Sprintf("%s:%d:%d", q.Name, q.Qtype, q.Qclass)
	r, rtt, err, shared := c.group.Do(key, func() (*Msg, time.Duration, error) {
		// When we're doing singleflight we don't want one context cancelation, cancel _all_ outstanding queries.
		// Hence we ignore the context and use Background().
		return c.exchangeContext(context.Background(), m, conn)
	})
	if r != nil && shared {
		r = r.Copy()
	}

	return r, rtt, err
}

func (c *Client) exchangeContext(ctx context.Context, m *Msg, co *Conn) (r *Msg, rtt time.Duration, err error) {
	opt := m.IsEdns0()
	// If EDNS0 is used use that for size.
	if opt != nil && opt.UDPSize() >= MinMsgSize {
		co.UDPSize = opt.UDPSize()
	}
	// Otherwise use the client's configured UDP size.
	if opt == nil && c.UDPSize >= MinMsgSize {
		co.UDPSize = c.UDPSize
	}

	// write with the appropriate write timeout
	t := time.Now()
	writeDeadline := t.Add(c.getTimeoutForRequest(c.writeTimeout()))
	readDeadline := t.Add(c.getTimeoutForRequest(c.readTimeout()))
	if deadline, ok := ctx.Deadline(); ok {
		if deadline.Before(writeDeadline) {
			writeDeadline = deadline
		}
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
	}
	if c.Net != "squic" {
		co.SetWriteDeadline(writeDeadline)
		co.SetReadDeadline(readDeadline)
	}

	co.TsigSecret, co.TsigProvider = c.TsigSecret, c.TsigProvider

	if err = co.WriteMsg(m); err != nil {
		return nil, 0, err
	}
	//---------------------------------------------------------------
	/* if c.Net == "squic" {

	} else */if isPacketConn(co.Conn) {
		for {
			r, err = co.ReadMsg()
			// Ignore replies with mismatched IDs because they might be
			// responses to earlier queries that timed out.
			if err != nil || r.Id == m.Id {
				break
			}
		}
	} else {
		r, err = co.ReadMsg()
		if err == nil && r.Id != m.Id {
			err = ErrId
		}
	}
	rtt = time.Since(t)
	return r, rtt, err
}

var bufferPool sync.Pool

// AcquireBuf returns an buf from pool
func AcquireBuf(size uint16) []byte {
	x := bufferPool.Get()
	if x == nil {
		return make([]byte, size)
	}
	buf := *(x.(*[]byte))
	if cap(buf) < int(size) {
		return make([]byte, size)
	}
	return buf[:size]
}

// ReleaseBuf returns buf to pool
func ReleaseBuf(buf []byte) {
	bufferPool.Put(&buf)
}

// ReadMsg reads a message from the connection co.
// If the received message contains a TSIG record the transaction signature
// is verified. This method always tries to return the message, however if an
// error is returned there are no guarantees that the returned message is a
// valid representation of the packet read.
func (co *Conn) ReadMsg() (*Msg, error) {
	var (
		p   []byte
		err error
	)

	if isDoQ := co.qstream != nil; isDoQ {

		var msglength uint16
		if err := binary.Read(*co.qstream, binary.BigEndian, &msglength); err != nil {
			return nil, err
		}
		p = AcquireBuf(msglength)

		// respBuf := p
		// var buff *bytes.Buffer = bytes.NewBuffer(respBuf)
		var n int
		n, err = io.ReadFull(*co.qstream, p)
		if err != nil {
			fmt.Printf("readFull failed: %v read: %v \n", err.Error(), n)
			return nil, err
		}

	} else {
		//------------------------------------------
		p, err = co.ReadMsgHeader(nil)
		if err != nil {
			return nil, err
		}
	}
	defer ReleaseBuf(p)
	m := new(Msg)
	if err := m.Unpack(p); err != nil {
		// If an error was returned, we still want to allow the user to use
		// the message, but naively they can just check err if they don't want
		// to use an erroneous message
		return m, err
	}
	if t := m.IsTsig(); t != nil {
		// Need to work on the original message p, as that was used to calculate the tsig.
		err = TsigVerifyWithProvider(p, co.tsigProvider(), co.tsigRequestMAC, false)
	}
	return m, err
}

// ReadMsgHeader reads a DNS message, parses and populates hdr (when hdr is not nil).
// Returns message as a byte slice to be parsed with Msg.Unpack later on.
// Note that error handling on the message body is not possible as only the header is parsed.
func (co *Conn) ReadMsgHeader(hdr *Header) ([]byte, error) {
	var (
		p   []byte
		n   int
		err error
	)

	if isPacketConn(co.Conn) {
		if co.UDPSize > MinMsgSize {
			p = make([]byte, co.UDPSize)
		} else {
			p = make([]byte, MinMsgSize)
		}
		n, err = co.Read(p)
	} else {
		var length uint16
		if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
			return nil, err
		}

		p = make([]byte, length)
		n, err = io.ReadFull(co.Conn, p)
	}

	if err != nil {
		return nil, err
	} else if n < headerSize {
		return nil, ErrShortRead
	}

	p = p[:n]
	if hdr != nil {
		dh, _, err := unpackMsgHdr(p, 0)
		if err != nil {
			return nil, err
		}
		*hdr = dh
	}
	return p, err
}

func (co *Conn) ReadBuff(buff *bytes.Buffer) (n int, m int, sizes []uint16, err error) {
	n = 0 // how many bytes in total did we read
	m = 0 // how many messages did we read

	if isDoQ := co.qstream != nil; isDoQ {
		for {
			//startReadMsg:
			var msglength uint16
			if err := binary.Read(*co.qstream, binary.BigEndian, &msglength); err != nil {
				if m == 0 {
					return 0, m, sizes, err
				} else {
					// we expect io.EOF here
					return n, m, sizes, nil
				}
			}
			sizes = append(sizes, msglength)
			// p = AcquireBuf(msglength)

			// respBuf := p
			// var buff *bytes.Buffer = bytes.NewBuffer(respBuf)
			//		var n int
			//n, err = io.ReadFull(*co.qstream, p)
			//n, err = io.ReadAtLeast(*co.qstream, p, int(msglength))
			nn, err := io.CopyN(buff, *co.qstream, int64(msglength))
			if err != nil && err != io.EOF {

				fmt.Printf("readFull failed: %v read: %v instead of %v \n", err.Error(), nn, msglength)
				n += int(nn)

				return int(nn), m, sizes, err
			}
			n += int(nn)
			m += 1

			/*if n > int64(msglength) {
				fmt.Printf("read more(%v) than message size(%v). Probably more than one response on the same stream \n", n, msglength)
			}*/
		}
		return int(n), m, sizes, nil
	}

	if co.Conn == nil {
		return 0, m, sizes, ErrConnEmpty
	}

	if isPacketConn(co.Conn) {
		// UDP connection
		buff.Grow(MaxMsgSize)
		n, e := co.Conn.Read(buff.Bytes())
		return n, 1, sizes, e
	}

	var length uint16
	if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
		return 0, 0, sizes, err
	}
	sizes = append(sizes, length)
	/*if int(length) > len(p) {
		return 0, io.ErrShortBuffer
	}*/

	//return io.ReadFull(co.Conn, p[:length])
	tmp, e := io.Copy(buff, co.Conn)
	return int(tmp), 1, sizes, e
}

// Read implements the net.Conn read method.
func (co *Conn) Read(p []byte) (n int, err error) {

	if isDoQ := co.qstream != nil; isDoQ {

		var msglength uint16
		if err := binary.Read(*co.qstream, binary.BigEndian, &msglength); err != nil {
			return 0, err
		}
		// p = AcquireBuf(msglength)

		// respBuf := p
		// var buff *bytes.Buffer = bytes.NewBuffer(respBuf)
		var n int
		//n, err = io.ReadFull(*co.qstream, p)
		n, err = io.ReadAtLeast(*co.qstream, p, int(msglength))
		if err != nil {
			fmt.Printf("readFull failed: %v read: %v \n", err.Error(), n)
			return n, err
		}
		if n > int(msglength) {
			fmt.Printf("read more(%v) than message size(%v). Probably more than one response on the same stream \n", n, msglength)
		}
		return n, nil
	}

	if co.Conn == nil {
		return 0, ErrConnEmpty
	}

	if isPacketConn(co.Conn) {
		// UDP connection
		return co.Conn.Read(p)
	}

	var length uint16
	if err := binary.Read(co.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	if int(length) > len(p) {
		return 0, io.ErrShortBuffer
	}

	return io.ReadFull(co.Conn, p[:length])
}

// WriteMsg sends a message through the connection co.
// If the message m contains a TSIG record the transaction
// signature is calculated.
func (co *Conn) WriteMsg(m *Msg) (err error) {
	var out []byte
	if t := m.IsTsig(); t != nil {
		// Set tsigRequestMAC for the next read, although only used in zone transfers.
		out, co.tsigRequestMAC, err = TsigGenerateWithProvider(m, co.tsigProvider(), co.tsigRequestMAC, false)
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	_, err = co.Write(out)
	return err
}

// AddPrefix adds a 2-byte prefix with the DNS message length.
/*func addPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}*/

// Write implements the net.Conn Write method.
func (co *Conn) Write(p []byte) (int, error) {
	if len(p) > MaxMsgSize {
		return 0, errors.New("message too large")
	}

	var err error
	if isDoQ := co.QuicEarlySession != nil; isDoQ {
		var stream quic.Stream

		stream, err = co.QuicEarlySession.OpenStreamSync(context.Background())

		if err != nil {
			fmt.Printf("failed to open Stream: %v \n", err.Error())
		}

		rawMsg := addPrefix(p)
		if len(rawMsg) != len(p)+2 {
			fmt.Printf("Add prefix failed! len(rawMsg): %v\n", len(rawMsg))
		}
		var n int
		n, err = stream.Write(rawMsg)
		if err != nil {
			return n, fmt.Errorf("failed to write to a QUIC stream: %w", err)
		}
		if n != len(p)+2 {
			fmt.Printf("wrote %v but was supposed to write %v", n, len(p)+2)
		}

		// The client MUST send the DNS query over the selected stream, and MUST
		// indicate through the STREAM FIN mechanism that no further data will
		// be sent on that stream. Note, that stream.Close() closes the
		// write-direction of the stream, but does not prevent reading from it.
		_ = stream.Close()
		co.qstream = &stream
		return n, nil

	}

	if isPacketConn(co.Conn) {
		return co.Conn.Write(p)
	}

	msg := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(msg, uint16(len(p)))
	copy(msg[2:], p)
	return co.Conn.Write(msg)
}

// Return the appropriate timeout for a specific request
func (c *Client) getTimeoutForRequest(timeout time.Duration) time.Duration {
	var requestTimeout time.Duration
	if c.Timeout != 0 {
		requestTimeout = c.Timeout
	} else {
		requestTimeout = timeout
	}
	// net.Dialer.Timeout has priority if smaller than the timeouts computed so
	// far
	if c.Dialer != nil && c.Dialer.Timeout != 0 {
		if c.Dialer.Timeout < requestTimeout {
			requestTimeout = c.Dialer.Timeout
		}
	}
	return requestTimeout
}

// Dial connects to the address on the named network.
func Dial(network, address string) (conn *Conn, err error) {
	conn = new(Conn)
	conn.Conn, err = net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ExchangeContext performs a synchronous UDP query, like Exchange. It
// additionally obeys deadlines from the passed Context.
func ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, err error) {
	client := Client{Net: "udp"}
	r, _, err = client.ExchangeContext(ctx, m, a)
	// ignoring rtt to leave the original ExchangeContext API unchanged, but
	// this function will go away
	return r, err
}

// ExchangeContext performs a synchronous UDP query, like Exchange. It
// additionally obeys deadlines from the passed Context.
func ExchangeContextProto(ctx context.Context, m *Msg, a string, proto string) (r *Msg, err error) {

	client := Client{Net: proto}
	r, _, err = client.ExchangeContext(ctx, m, a)
	// ignoring rtt to leave the original ExchangeContext API unchanged, but
	// this function will go away
	return r, err
}

// ExchangeConn performs a synchronous query. It sends the message m via the connection
// c and waits for a reply. The connection c is not closed by ExchangeConn.
// Deprecated: This function is going away, but can easily be mimicked:
//
//	co := &dns.Conn{Conn: c} // c is your net.Conn
//	co.WriteMsg(m)
//	in, _  := co.ReadMsg()
//	co.Close()
func ExchangeConn(c net.Conn, m *Msg) (r *Msg, err error) {
	println("dns: ExchangeConn: this function is deprecated")
	co := new(Conn)
	co.Conn = c
	if err = co.WriteMsg(m); err != nil {
		return nil, err
	}
	r, err = co.ReadMsg()
	if err == nil && r.Id != m.Id {
		err = ErrId
	}
	return r, err
}

// DialTimeout acts like Dial but takes a timeout.
func DialTimeout(network, address string, timeout time.Duration) (conn *Conn, err error) {
	client := Client{Net: network, Dialer: &net.Dialer{Timeout: timeout}}
	return client.Dial(address)
}

// DialWithTLS connects to the address on the named network with TLS.
func DialWithTLS(network, address string, tlsConfig *tls.Config) (conn *Conn, err error) {
	if !strings.HasSuffix(network, "-tls") {
		network += "-tls"
	}
	client := Client{Net: network, TLSConfig: tlsConfig}
	return client.Dial(address)
}

// DialTimeoutWithTLS acts like DialWithTLS but takes a timeout.
func DialTimeoutWithTLS(network, address string, tlsConfig *tls.Config, timeout time.Duration) (conn *Conn, err error) {
	if !strings.HasSuffix(network, "-tls") {
		network += "-tls"
	}
	client := Client{Net: network, Dialer: &net.Dialer{Timeout: timeout}, TLSConfig: tlsConfig}
	return client.Dial(address)
}

// ExchangeContext acts like Exchange, but honors the deadline on the provided
// context, if present. If there is both a context deadline and a configured
// timeout on the client, the earliest of the two takes effect.
func (c *Client) ExchangeContext(ctx context.Context, m *Msg, a string) (r *Msg, rtt time.Duration, err error) {
	conn, err := c.DialContext(ctx, a)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	return c.exchangeWithConnContext(ctx, m, conn)
}
