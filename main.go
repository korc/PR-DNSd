package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/miekg/dns"
)

type debounceInfo struct {
	tm  time.Time
	cnt int
}

type handler struct {
	dns.Handler
	ClientTimeout      time.Duration
	clients            map[string]*dns.Client
	servers            map[string]string
	ptrMap             map[string]string
	lastResultSent     map[string]debounceInfo
	lastResultSentLock sync.Mutex
	ptrMapLock         sync.Mutex
	DebounceDelay      time.Duration
	DebounceCount      int
	StoreDB            *badger.DB
	IsSilent           bool
}

func (h *handler) checkNoDoS(w dns.ResponseWriter) bool {
	remAddr := w.RemoteAddr()
	if a, ok := remAddr.(*net.UDPAddr); ok {
		ip := a.IP.String()
		h.lastResultSentLock.Lock()
		defer h.lastResultSentLock.Unlock()

		if h.lastResultSent == nil {
			h.lastResultSent = make(map[string]debounceInfo)
		}
		if lastReply, has := h.lastResultSent[ip]; has {
			if time.Now().Before(lastReply.tm.Add(h.DebounceDelay)) {
				log.Printf("Debounce delay (%s) since last reply not passed, count = %d / %d",
					h.DebounceDelay, lastReply.cnt, h.DebounceCount)
				if lastReply.cnt <= 0 {
					return false
				}
				h.lastResultSent[ip] = debounceInfo{tm: time.Now(), cnt: lastReply.cnt - 1}
			} else {
				h.lastResultSent[ip] = debounceInfo{tm: time.Now(), cnt: h.DebounceCount}
			}
		} else {
			h.lastResultSent[ip] = debounceInfo{tm: time.Now(), cnt: h.DebounceCount}
		}
	}
	return true
}

func (h *handler) writeMsg(w dns.ResponseWriter, r *dns.Msg) error {
	if err := w.WriteMsg(r); err != nil {
		log.Printf("Error sending msg to %s: %s", w.RemoteAddr(), err)
		return err
	}
	return nil
}

type errNoUpstream error

func (h *handler) SetUpstream(upstream []string) {
	h.clients = map[string]*dns.Client{}
	h.servers = map[string]string{}
	for _, up := range upstream {
		domain := ""
		proto := "udp"
		if eqIdx := strings.Index(up, "="); eqIdx >= 0 {
			domain, up = up[:eqIdx], up[eqIdx+1:]
		}
		if protoIdx := strings.Index(up, "://"); protoIdx >= 0 {
			proto, up = up[:protoIdx], up[protoIdx+3:]
		}
		h.clients[domain] = &dns.Client{Net: proto, Timeout: h.ClientTimeout}
		h.servers[domain] = up
	}
}

func (h *handler) upstreamExchange(r *dns.Msg) (*dns.Msg, time.Duration, error) {
	qName := strings.TrimSuffix(r.Question[0].Name, ".")
	for dotIdx, domain := 0, qName; dotIdx >= 0; dotIdx = strings.Index(domain, ".") {
		domain = domain[dotIdx:]
		if cl, have := h.clients[domain]; have {
			log.Printf("[%02x] will use %s for %s", r.Id, h.servers[domain], domain)
			return cl.Exchange(r, h.servers[domain])
		}
		if dotIdx > 0 {
			domain = domain[1:]
		}
	}

	if cl, have := h.clients[""]; have {
		return cl.Exchange(r, h.servers[""])
	}
	return nil, 0, errNoUpstream(errors.New("no upstream server set"))
}

func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if !h.checkNoDoS(w) {
		log.Printf("Dropping, DoS check failed to %s", w.RemoteAddr())
		return
	}
	if h.ptrMap == nil {
		h.ptrMap = make(map[string]string)
	}
	if len(r.Question) < 1 {
		log.Printf("Query without questions from %s?", w.RemoteAddr())
		return
	}
	q := r.Question[0]
	if !h.IsSilent {
		log.Printf("Query from %s: %s", w.RemoteAddr(), q.String())
	}

	if q.Qtype == dns.TypePTR && q.Qclass == dns.ClassINET {
		if v, has := h.ptrMap[q.Name]; has {
			if !h.IsSilent {
				log.Printf("Replying with cached PTR: %#v = %#v", q.Name, v)
			}
			_ = h.writeMsg(w, &dns.Msg{
				MsgHdr:   dns.MsgHdr{Id: r.MsgHdr.Id, Response: true, RecursionDesired: r.RecursionDesired, RecursionAvailable: true},
				Question: r.Question,
				Answer: []dns.RR{&dns.PTR{
					Hdr: dns.RR_Header{Name: q.Name, Class: q.Qclass, Rrtype: q.Qtype, Ttl: 300},
					Ptr: v,
				}}})
			return
		}
		log.Printf("PTR not in cache: %#v", q.Name)
	}
	if !r.RecursionDesired {
		log.Printf("[%02x] Client %s doesn't want recursion", r.Id, w.RemoteAddr())
		_ = h.writeMsg(w, &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: r.MsgHdr.Id, Response: true, Rcode: dns.RcodeServerFailure}})
		return
	}
	resp, rtt, err := h.upstreamExchange(r)
	if err != nil {
		log.Printf("[%02x] Error getting response: %s", r.Id, err)
		switch err.(type) {
		case *net.OpError, errNoUpstream:
			h.writeMsg(w,
				&dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id: r.MsgHdr.Id, Response: true,
						RecursionDesired: r.RecursionDesired, RecursionAvailable: true,
						Rcode: dns.RcodeServerFailure,
					},
					Question: r.Question})
		}
		return
	}
	if !h.IsSilent {
		log.Printf("[%02x] Got response (rtt=%s)\n%s", r.Id, rtt, resp)
	}
	for _, answ := range resp.Answer {
		addrString := ""
		switch a := answ.(type) {
		case *dns.AAAA:
			addrString = a.AAAA.String()
		case *dns.A:
			addrString = a.A.String()
		default:
			continue
		}
		ptr, err := dns.ReverseAddr(addrString)
		if err != nil {
			log.Printf("Could not transform to reverse address: %#v", answ)
			continue
		}
		h.ptrMapLock.Lock()
		h.ptrMap[ptr] = q.Name
		h.ptrMapLock.Unlock()
		if h.StoreDB != nil {
			if err := h.StoreDB.Update(func(txn *badger.Txn) error {
				if err := txn.Set([]byte(ptr), []byte(q.Name)); err != nil {
					return err
				}
				return nil
			}); err != nil {
				log.Printf("Cannot update database: %s", err)
			}
		}
		if !h.IsSilent {
			log.Printf("caching answer for %s as %s (%s)", addrString, q.Name, ptr)
		}
	}
	_ = h.writeMsg(w, resp)
}

func (h *handler) ReadDb(fname string) (err error) {
	if h.StoreDB, err = badger.Open(badger.DefaultOptions(fname)); err != nil {
		return err
	}
	h.ptrMap = make(map[string]string)
	if err := h.StoreDB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				h.ptrMap[string(k)] = string(v)
				if !h.IsSilent {
					log.Printf("key=%s, value=%s\n", k, v)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

const (
	setcapHelp    = "sudo setcap cap_net_bind_service,cap_sys_chroot=ep"
	chrootHelp    = "-chroot ''"
	listenHelp    = "-listen [<ip>]:<port> with port>1024"
	tlsListenHelp = "-tlslisten [<ip>]:<port> with port>1024"
)

type ArrayFlag []string

func (f *ArrayFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *ArrayFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	h := &handler{}

	var upstream ArrayFlag
	flag.Var(&upstream, "upstream", "upstream DNS server (tcp-tls:// prefix for DoT), multi-val, can prefix with .domain=")
	listenAddrFlag := flag.String("listen", ":53", "listen address")
	tlsListenFlag := flag.String("tlslisten", ":853", "TCP-TLS listener address")
	certFlag := flag.String("cert", "", "TCP-TLS listener certificate (required for tls listener)")
	keyFlag := flag.String("key", "", "TCP-TLS certificate key (default same as -cert value)")
	debounceDelayFlag := flag.String("debounce", "200ms",
		"Required time duration between UDP replies to single IP to prevent DoS")
	flag.IntVar(&h.DebounceCount, "count", 100,
		"Count of replies allowed before debounce delay is applied")
	storeFlag := flag.String("store", "", "Store PTR data to specified file")
	chrootFlag := flag.String("chroot", DefaultChroot, "chroot to directory after start")
	flag.BoolVar(&h.IsSilent, "silent", false, "Don't report normal data")
	flag.DurationVar(&h.ClientTimeout, "ctmout", 0, "Client timeout for upstream queries")
	flag.Parse()

	if len(upstream) == 0 {
		upstream.Set("tcp-tls://1.1.1.1:853")
	}
	h.SetUpstream(upstream)

	var tlsServer *dns.Server
	var srv *dns.Server

	if *tlsListenFlag != "" && *certFlag != "" {
		if *keyFlag == "" {
			*keyFlag = *certFlag
		}
		cert, err := tls.LoadX509KeyPair(*certFlag, *keyFlag)
		if err != nil {
			log.Fatalf("Cannot load X509 Cert/Key from %#v/%#v: %s", *certFlag, *keyFlag, err)
		}

		tlsServer = &dns.Server{
			Addr:      *tlsListenFlag,
			Net:       "tcp-tls",
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
			Handler:   h,
		}
	}

	if *chrootFlag != "" {
		if err := doChroot(*chrootFlag); err != nil {
			if err == syscall.EPERM {
				log.Printf("Permission error, perhaps '%s %s' or %s will help?",
					setcapHelp, os.Args[0], chrootHelp)
			}
			log.Fatalf("Cannot chroot to %#v: %s", *chrootFlag, err)
		}
		if err := os.Chdir("/"); err != nil {
			log.Fatalf("Cannot change to chrooted directory %#v: %s", *chrootFlag, err)
		}
	}

	if *storeFlag != "" {
		if err := h.ReadDb(*storeFlag); err != nil {
			log.Fatalf("Cannot read ptr data from badger DB at %#v: %s", *storeFlag, err)
		}
		defer h.StoreDB.Close()
	}

	if *debounceDelayFlag != "" {
		var err error
		h.DebounceDelay, err = time.ParseDuration(*debounceDelayFlag)
		if err != nil {
			log.Fatalf("Cannot parse delay %#v: %s", *debounceDelayFlag, err)
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	if *listenAddrFlag != "" {
		srv = &dns.Server{Addr: *listenAddrFlag, Net: "udp", Handler: h, ReusePort: true}
		go func() {
			if !h.IsSilent {
				log.Printf("ListenAndServe on %s", *listenAddrFlag)
			}
			err := srv.ListenAndServe()
			if err != nil {
				if netOpErr, ok := err.(*net.OpError); ok {
					if scerr, ok := netOpErr.Err.(*os.SyscallError); ok {
						if scerr.Err == syscall.EACCES {
							log.Printf("Permission error, perhaps '%s %s' or %s will help?",
								setcapHelp, os.Args[0], listenHelp)
						}
					}
				}
				log.Fatal("Cannot serve DNS server: ", err)
			}
		}()
	}

	if tlsServer != nil {
		go func() {
			if !h.IsSilent {
				log.Printf("TLS ListenAndServe on %s", *tlsListenFlag)
			}
			err := tlsServer.ListenAndServe()
			if err != nil {
				if netOpErr, ok := err.(*net.OpError); ok {
					if scerr, ok := netOpErr.Err.(*os.SyscallError); ok {
						if scerr.Err == syscall.EACCES {
							log.Printf("Permission error, perhaps '%s %s' or %s will help?",
								setcapHelp, os.Args[0], tlsListenHelp)
						}
					}
				}
				log.Fatalf("Cannot serve TCP-TLS DNS server on %#v: %s", *tlsListenFlag, err)
			}
		}()
	} else if srv == nil {
		log.Fatalf("No DNS server listeners defined")
	}

	s := <-c
	if !h.IsSilent {
		log.Printf("Signal received: %s", s)
	}
}
