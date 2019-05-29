package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func mapKeys(m map[string]uint16) (keys []string) {
	keys = []string{}
	for k := range dns.StringToType {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return
}

func main() {
	noRecurseFlag := flag.Bool("norecurse", false, "Disable recursion")
	verboseFlag := flag.Bool("verbose", false, "Operate verbosely")
	netProtoFlag := flag.String("netproto", "udp", "Protocol to use (one of udp, tcp or tcp-tls)")
	timeout := flag.String("timeout", "", "Timeout")
	serverFlag := flag.String("server", "127.0.0.1:53", "DNS server to query")
	caCertFlag := flag.String("capem", "", "CA certificates for TLS")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		log.Fatalf("Usage: %s [<options>] <query> [<type> [<class>]]", path.Base(os.Args[0]))
	}

	req := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: dns.Id(), RecursionDesired: !*noRecurseFlag},
		Question: []dns.Question{{Name: args[0], Qclass: dns.ClassINET, Qtype: dns.TypeANY}},
	}

	if len(args) > 1 {
		if t, ok := dns.StringToType[args[1]]; ok {
			req.Question[0].Qtype = t
		} else {
			log.Printf("Available types: %s", strings.Join(mapKeys(dns.StringToType), ", "))
			log.Fatalf("Don't know how to handle type: %s", args[1])
		}
	}
	if len(args) > 2 {
		if c, ok := dns.StringToClass[args[2]]; ok {
			req.Question[0].Qclass = c
		} else {
			log.Fatalf("Don't know how to handle class: %s (available: %s)", args[2],
				strings.Join(mapKeys(dns.StringToClass), ", "))
		}
	}

	clnt := dns.Client{Net: *netProtoFlag}
	if *timeout != "" {
		var err error
		clnt.Timeout, err = time.ParseDuration(*timeout)
		if err != nil {
			log.Fatalf("Cannot parse timeout %#v: %s", *timeout, err)
		}
	}

	if *caCertFlag != "" {
		cp := x509.NewCertPool()
		pem, err := ioutil.ReadFile(*caCertFlag)
		if err != nil {
			log.Fatalf("Failed to read client certificate authority: %v", err)
		}
		cp.AppendCertsFromPEM(pem)
		clnt.TLSConfig = &tls.Config{RootCAs: cp}
	}

	if *verboseFlag {
		log.Printf("Sending request %#v to %#v", req, *serverFlag)
	}
	resp, rtt, err := clnt.Exchange(req, *serverFlag)
	if err != nil {
		log.Fatalf("Response error: %s", err)
	}
	if *verboseFlag {
		log.Printf("Response: %#v (rtt=%v)", resp, rtt)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Fatal("Could not output JSON: ", err)
	}
}
