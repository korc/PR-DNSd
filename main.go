package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/miekg/dns"
)

type cachedResponse struct {
	ResponseTime time.Time
	Resp         *dns.Msg
}

type debounceInfo struct {
	tm  time.Time
	cnt int
}

type handler struct {
	dns.Handler
	Upstream           string
	Client             *dns.Client
	ptrMap             map[string]string
	lastResultSent     map[string]debounceInfo
	lastResultSentLock sync.Mutex
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
				} else {
					h.lastResultSent[ip] = debounceInfo{tm: time.Now(), cnt: lastReply.cnt - 1}
				}
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
		} else {
			log.Printf("PTR not in cache: %#v", q.Name)
		}
	}
	if !r.RecursionDesired {
		log.Printf("Client %s doesn't want recursion", w.RemoteAddr())
		_ = h.writeMsg(w, &dns.Msg{
			MsgHdr: dns.MsgHdr{Id: r.MsgHdr.Id, Response: true, Rcode: dns.RcodeServerFailure}})
		return
	}
	if h.Client == nil {
		h.Client = &dns.Client{Net: "udp"}
	}
	resp, rtt, err := h.Client.Exchange(r, h.Upstream)
	if err != nil {
		log.Printf("Error getting response from %#v: %s", h.Upstream, err)
		if _, ok := err.(*net.OpError); ok {
			_ = h.writeMsg(w,
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
		log.Printf("Got response from %#v (rtt=%s):\n%s", h.Upstream, rtt, resp)
	}
	for _, answ := range resp.Answer {
		addrString := ""
		switch answ.(type) {
		case *dns.AAAA:
			addrString = answ.(*dns.AAAA).AAAA.String()
		case *dns.A:
			addrString = answ.(*dns.A).A.String()
		default:
			continue
		}
		ptr, err := dns.ReverseAddr(addrString)
		if err != nil {
			log.Printf("Could not transform to reverse address: %#v", answ)
			continue
		}
		h.ptrMap[ptr] = q.Name
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
	opts := badger.DefaultOptions
	opts.Dir = fname
	opts.ValueDir = fname
	if h.StoreDB, err = badger.Open(opts); err != nil {
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

func main() {
	upstreamServerFlag := flag.String("upstream", "127.0.0.1:53", "upstream DNS server")
	listenAddrFlag := flag.String("listen", ":53", "listen address")
	tlsListenFlag := flag.String("tlslisten", "", "TCP-TLS listener address (requires -cert)")
	certFlag := flag.String("cert", "server.crt", "TCP-TLS listener certificate")
	keyFlag := flag.String("key", "", "TCP-TLS certiicate key (default same as -cert value)")
	debounceDelayFlag := flag.String("debounce", "200ms",
		"Required time duration between UDP replies to single IP to prevent DoS")
	debounceCountFlag := flag.Int("count", 10,
		"Count of replies allowed before debounce delay is applied")
	storeFlag := flag.String("store", "", "Store PTR data to specified file")
	chrootFlag := flag.String("chroot", "/var/tmp", "chroot to directory after start")
	silentFlag := flag.Bool("silent", false, "Don't report normal data")
	clientTimeoutFlag := flag.String("ctmout", "", "Client timeout")
	flag.Parse()

	h := &handler{Upstream: *upstreamServerFlag, DebounceCount: *debounceCountFlag, IsSilent: *silentFlag}
	if *clientTimeoutFlag != "" {
		cltmout, err := time.ParseDuration(*clientTimeoutFlag)
		if err != nil {
			log.Fatal("Cannot parse client timeout: ", err)
		}
		h.Client = &dns.Client{Net: "udp", Timeout: cltmout}
	}

	var tlsServer *dns.Server
	var srv *dns.Server

	if *tlsListenFlag != "" {
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
		if err := syscall.Chroot(*chrootFlag); err != nil {
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
		srv = &dns.Server{Addr: *listenAddrFlag, Net: "udp", Handler: h}
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
				log.Fatalf("Cannot serve TCP-TLS DNS server on %#v: %s", *tlsListenFlag, err)
			}
		}()
	}

	s := <-c
	if !h.IsSilent {
		log.Printf("Signal received: %s", s)
	}
}
