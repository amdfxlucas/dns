package dns

import (
	"bytes"
	"fmt"
	"time"
)

// Envelope is used when doing a zone transfer with a remote server.
type Envelope struct {
	RR    []RR  // The set of RRs in the answer section of the xfr reply message.
	Error error // If something went wrong, this contains the error.
}

// A Transfer defines parameters that are used during a zone transfer.
type Transfer struct {
	*Conn
	DialTimeout    time.Duration     // net.DialTimeout, defaults to 2 seconds
	ReadTimeout    time.Duration     // net.Conn.SetReadTimeout value for connections, defaults to 2 seconds
	WriteTimeout   time.Duration     // net.Conn.SetWriteTimeout value for connections, defaults to 2 seconds
	TsigProvider   TsigProvider      // An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
	TsigSecret     map[string]string // Secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2)
	tsigTimersOnly bool
}

func (t *Transfer) Close() error {
	return t.Conn.Close()
}

func (t *Transfer) tsigProvider() TsigProvider {
	if t.TsigProvider != nil {
		return t.TsigProvider
	}
	if t.TsigSecret != nil {
		return tsigSecretProvider(t.TsigSecret)
	}
	return nil
}

// TODO: Think we need to away to stop the transfer

// In performs an incoming transfer with the server in a.
// If you would like to set the source IP, or some other attribute
// of a Dialer for a Transfer, you can do so by specifying the attributes
// in the Transfer.Conn:
//
//	d := net.Dialer{LocalAddr: transfer_source}
//	con, err := d.Dial("tcp", master)
//	dnscon := &dns.Conn{Conn:con}
//	transfer = &dns.Transfer{Conn: dnscon}
//	channel, err := transfer.In(message, master)
func (t *Transfer) In(q *Msg, a string) (env chan *Envelope, err error) {
	switch q.Question[0].Qtype {
	case TypeAXFR, TypeIXFR:
	default:
		return nil, &Error{"unsupported question type"}
	}

	timeout := dnsTimeout
	if t.DialTimeout != 0 {
		timeout = t.DialTimeout
	}

	if t.Conn == nil {
		t.Conn, err = DialTimeout("tcp", a, timeout)
		if err != nil {
			return nil, err
		}
	}

	if err := t.WriteMsg(q); err != nil {
		return nil, err
	}

	env = make(chan *Envelope)
	switch q.Question[0].Qtype {
	case TypeAXFR:
		go t.inAxfr(q, env)
	case TypeIXFR:
		go t.inIxfr(q, env)
	}

	return env, nil
}

/*
\param msgs array of responses to a request that generated a large answer i.e. zone transfer
*/
func joinMsgs(msgs []*Msg) *Msg {

	res := new(Msg)
	first := true
	var qname string
	var qtype uint16
	for _, m := range msgs {
		if first {

			qname = m.Question[0].Name
			qtype = m.Question[0].Qtype
			res.Id = m.Id
			res.Response = m.Response
			// res.Zero =
			// res.AuthenticatedData =
			res.Opcode = m.Opcode
			if m.Opcode == OpcodeQuery {
				res.RecursionDesired = m.RecursionDesired // Copy rd bit
				res.CheckingDisabled = m.CheckingDisabled // Copy cd bit
			}
			res.Rcode = m.Rcode
			if len(m.Question) > 0 {
				res.Question = make([]Question, 1)
				res.Question[0] = m.Question[0]
			}
			first = false
		}
		// all messages must be responses to the same request
		if qname != m.Question[0].Name || qtype != m.Question[0].Qtype {
			return nil
		}

		res.Answer = append(res.Answer, m.Answer...)
		res.Extra = append(res.Extra, m.Extra...)
		res.Ns = append(res.Ns, m.Ns...)
	}

	return res
}

func (t *Transfer) inAxfr(q *Msg, c chan *Envelope) {
	first := true
	defer t.Close()
	defer close(c)
	timeout := dnsTimeout
	if t.ReadTimeout != 0 {
		timeout = t.ReadTimeout
	}
	for {
		t.Conn.SetReadDeadline(time.Now().Add(timeout))
		ins, err := t.ReadMsgs()
		if err != nil {
			c <- &Envelope{nil, err}
			return
		}
		in := joinMsgs(ins)
		if in == nil {
			fmt.Print(" joinMsgs failed in inAxfr \n")
			return
		}
		if q.Id != in.Id {
			c <- &Envelope{in.Answer, ErrId}
			return
		}
		if first {
			if in.Rcode != RcodeSuccess {
				c <- &Envelope{in.Answer, &Error{err: fmt.Sprintf(errXFR, in.Rcode)}}
				return
			}
			if !isSOAFirst(in) {
				c <- &Envelope{in.Answer, ErrSoa}
				return
			}
			first = !first
			// only one answer that is SOA, receive more
			if len(in.Answer) == 1 {
				t.tsigTimersOnly = true
				c <- &Envelope{in.Answer, nil}
				continue
			}
		}

		if !first {
			t.tsigTimersOnly = true // Subsequent envelopes use this.
			if isSOALast(in) {
				c <- &Envelope{in.Answer, nil}
				return
			}
			c <- &Envelope{in.Answer, nil}
		}
	}
}

func (t *Transfer) inIxfr(q *Msg, c chan *Envelope) {
	var serial uint32 // The first serial seen is the current server serial
	axfr := true
	n := 0
	qser := q.Ns[0].(*SOA).Serial
	defer t.Close()
	defer close(c)
	timeout := dnsTimeout
	if t.ReadTimeout != 0 {
		timeout = t.ReadTimeout
	}
	for {
		t.SetReadDeadline(time.Now().Add(timeout))
		in, err := t.ReadMsg()
		if err != nil {
			c <- &Envelope{nil, err}
			return
		}
		if q.Id != in.Id {
			c <- &Envelope{in.Answer, ErrId}
			return
		}
		if in.Rcode != RcodeSuccess {
			c <- &Envelope{in.Answer, &Error{err: fmt.Sprintf(errXFR, in.Rcode)}}
			return
		}
		if n == 0 {
			// Check if the returned answer is ok
			if !isSOAFirst(in) {
				c <- &Envelope{in.Answer, ErrSoa}
				return
			}
			// This serial is important
			serial = in.Answer[0].(*SOA).Serial
			// Check if there are no changes in zone
			if qser >= serial {
				c <- &Envelope{in.Answer, nil}
				return
			}
		}
		// Now we need to check each message for SOA records, to see what we need to do
		t.tsigTimersOnly = true
		for _, rr := range in.Answer {
			if v, ok := rr.(*SOA); ok {
				if v.Serial == serial {
					n++
					// quit if it's a full axfr or the the servers' SOA is repeated the third time
					if axfr && n == 2 || n == 3 {
						c <- &Envelope{in.Answer, nil}
						return
					}
				} else if axfr {
					// it's an ixfr
					axfr = false
				}
			}
		}
		c <- &Envelope{in.Answer, nil}
	}
}

// Out performs an outgoing transfer with the client connecting in w.
// Basic use pattern:
//
//	ch := make(chan *dns.Envelope)
//	tr := new(dns.Transfer)
//	var wg sync.WaitGroup
//	go func() {
//		tr.Out(w, r, ch)
//		wg.Done()
//	}()
//	ch <- &dns.Envelope{RR: []dns.RR{soa, rr1, rr2, rr3, soa}}
//	close(ch)
//	wg.Wait() // wait until everything is written out
//	w.Close() // close connection
//
// The server is responsible for sending the correct sequence of RRs through the channel ch.
func (t *Transfer) Out(w ResponseWriter, q *Msg, ch chan *Envelope) error {
	for x := range ch {
		r := new(Msg)
		// Compress?
		r.SetReply(q)
		r.Authoritative = true
		// assume it fits TODO(miek): fix
		r.Answer = append(r.Answer, x.RR...)
		if tsig := q.IsTsig(); tsig != nil && w.TsigStatus() == nil {
			r.SetTsig(tsig.Hdr.Name, tsig.Algorithm, tsig.Fudge, time.Now().Unix())
		}
		if err := w.WriteMsg(r); err != nil {
			return err
		}
		w.TsigTimersOnly(true)
	}
	return nil
}

// ReadMsg reads all messages from the transfer connection t.
func (t *Transfer) ReadMsgs() (msgs []*Msg, err error) {

	buff := bytes.NewBuffer(nil)
	buff.Grow(MaxMsgSize)

	n, c, sizes, err := t.Conn.ReadBuff(buff)
	if err != nil && n == 0 {
		return nil, err
	}
	fmt.Printf("received %v responses for zone Transfer request\n", c)
	p := buff.Bytes()
	var oldOff = 0
	for _, sz := range sizes {
		offset := oldOff + int(sz)
		m := new(Msg)

		if err := m.Unpack(p[oldOff:offset]); err != nil {
			return nil, err
		}
		if ts, tp := m.IsTsig(), t.tsigProvider(); ts != nil && tp != nil {
			// Need to work on the original message p, as that was used to calculate the tsig.
			err = TsigVerifyWithProvider(p[oldOff:offset], tp, t.tsigRequestMAC, t.tsigTimersOnly)
			t.tsigRequestMAC = ts.MAC
		}
		msgs = append(msgs, m)
		oldOff = int(offset)
	}
	return msgs, err
}

// ReadMsg reads a message from the transfer connection t.
func (t *Transfer) ReadMsg() (*Msg, error) {
	m := new(Msg)
	p := make([]byte, MaxMsgSize)
	n, err := t.Read(p)

	if err != nil && n == 0 {
		return nil, err
	}
	p = p[:n]
	if err := m.Unpack(p); err != nil {
		return nil, err
	}
	if ts, tp := m.IsTsig(), t.tsigProvider(); ts != nil && tp != nil {
		// Need to work on the original message p, as that was used to calculate the tsig.
		err = TsigVerifyWithProvider(p, tp, t.tsigRequestMAC, t.tsigTimersOnly)
		t.tsigRequestMAC = ts.MAC
	}
	return m, err
}

// WriteMsg writes a message through the transfer connection t.
func (t *Transfer) WriteMsg(m *Msg) (err error) {
	var out []byte
	if ts, tp := m.IsTsig(), t.tsigProvider(); ts != nil && tp != nil {
		out, t.tsigRequestMAC, err = TsigGenerateWithProvider(m, tp, t.tsigRequestMAC, t.tsigTimersOnly)
	} else {
		out, err = m.Pack()
	}
	if err != nil {
		return err
	}
	_, err = t.Write(out)
	return err
}

func isSOAFirst(in *Msg) bool {
	return len(in.Answer) > 0 &&
		in.Answer[0].Header().Rrtype == TypeSOA
}

func isSOALast(in *Msg) bool {
	return len(in.Answer) > 0 &&
		in.Answer[len(in.Answer)-1].Header().Rrtype == TypeSOA
}

const errXFR = "bad xfr rcode: %d"
