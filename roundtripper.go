package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type certAlgPair struct {
	PublicKeyAlgorithm string
	SignatureAlgorithm string
}

type timingTransport struct {
	DNSResolve   time.Duration `json:"dns_resolve"`
	FirstByte    time.Duration `json:"first_byte"`
	CompleteLoad time.Duration `json:"complete_load"`
	Connect      time.Duration `json:"connect"`
	TLSHandshake time.Duration `json:"tls_handshake"`
	WriteTime    time.Duration `json:"write_request"`

	CipherSuite     string                 `json:"cipher_suite"`
	Protocols       string                 `json:"protocols"`
	CertificateAlgs map[string]certAlgPair `json:"certificate_algs"`

	rsp *http.Response
}

var requestCounter = 0

func canonicalize(url *url.URL) (string, string) {
	host := url.Host
	port := "80"
	switch {
	case strings.Contains(url.Host, ":"):
		parts := strings.Split(url.Host, ":")
		host = parts[0]
		port = parts[1]
	case url.Scheme == "https":
		port = "443"
	}

	return host, port
}

func getLogger(enabled bool, url string) func(string, ...interface{}) {
	if enabled {
		return func(format string, args ...interface{}) {
			format = "%d - %s : " + format
			args = append([]interface{}{requestCounter, url}, args...)

			if !strings.HasSuffix(format, "\n") {
				format = format + "\n"
			}
			fmt.Printf(format, args...)
		}
	}

	return func(string, ...interface{}) {} // noop
}

func roundtrip(url string, printState bool) (res *timingTransport, err error) {
	show := getLogger(printState, url)
	defer func() { requestCounter++ }()
	res = new(timingTransport)
	show("Starting Timing")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	show("Validating request")
	err = validateRequest(req)
	if err != nil {
		return nil, err
	}
	show("Reqest is valid")

	// now just do a normal request
	show("Making full GET request")
	preNormal := time.Now()
	res.rsp, err = http.Get(url)
	if err != nil {
		return nil, err
	}

	res.CompleteLoad = time.Now().Sub(preNormal)
	show("Completed GET request in %s", res.CompleteLoad)

	host, port := canonicalize(req.URL)

	show("Resolving DNS")
	rawip, err := resolve(host, res)
	if err != nil {
		return nil, err
	}
	show("DNS successful: %s", rawip)

	var formattedIP string
	if ip := rawip.To4(); ip != nil {
		formattedIP = fmt.Sprintf("%s:%s", rawip, port)
	} else {
		formattedIP = fmt.Sprintf("[%s]:%s", rawip, port)
	}

	show("Going to dial %s", formattedIP)
	conn, err := net.Dial("tcp", formattedIP)
	if err != nil {
		return nil, err
	}
	show("Finished dialing")

	show("Checking HTTPS certs")
	tryHTTPS(&conn, req, res)
	show("Finished HTTPS check")

	show("Checking time to first byte")
	client := httputil.NewClientConn(conn, nil)
	preWrite := time.Now()
	client.Write(req)
	postWrite := time.Now()
	res.WriteTime = postWrite.Sub(preWrite)
	show("Wrote request")
	// discard the results, this should just read the first chunk from the sock
	client.Read(req)
	res.FirstByte = time.Now().Sub(postWrite)
	show("Finished checking time to first byte")
	return res, nil
}

func extractCertChain(state *tls.ConnectionState) map[string]certAlgPair {
	results := make(map[string]certAlgPair)

	for _, cert := range state.PeerCertificates {
		results[cert.Issuer.CommonName] = certAlgPair{
			PublicKeyAlgorithm: convertAlgorithm(cert.PublicKeyAlgorithm),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		}
	}

	return results
}

func resolve(host string, t *timingTransport) (*net.IP, error) {
	// host -> ip
	preDNS := time.Now()
	ips, err := net.LookupIP(host)
	t.DNSResolve = time.Now().Sub(preDNS)
	if err != nil {
		return nil, err
	}
	ip := ips[0]

	return &ip, nil
}

func tryHTTPS(conn *net.Conn, req *http.Request, t *timingTransport) (tlsConn net.Conn, err error) {
	if req.URL.Scheme == "https" {
		preTLS := time.Now()
		tlsConn = tls.Client(*conn, &tls.Config{ServerName: req.URL.Host})

		if err = tlsConn.(*tls.Conn).Handshake(); err != nil {
			return nil, err
		}

		if err = tlsConn.(*tls.Conn).VerifyHostname(req.URL.Host); err != nil {
			return nil, err
		}

		state := tlsConn.(*tls.Conn).ConnectionState()
		t.CipherSuite = convertCipher(state.CipherSuite)
		t.Protocols = state.NegotiatedProtocol
		t.CertificateAlgs = extractCertChain(&state)

		t.TLSHandshake = time.Now().Sub(preTLS)
	}

	return
}

func convertCipher(c uint16) string {
	// defined here: https://golang.org/pkg/crypto/tls/#pkg-constants
	switch {
	case c == 0x0005:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case c == 0x000a:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case c == 0x002f:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case c == 0x0035:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case c == 0x009c:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case c == 0x009d:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case c == 0xc007:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case c == 0xc009:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case c == 0xc00a:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case c == 0xc011:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case c == 0xc012:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case c == 0xc013:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case c == 0xc014:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case c == 0xc02f:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case c == 0xc02b:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case c == 0xc030:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case c == 0xc02c:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	}
	return "UNKNOWN"
}

func convertAlgorithm(p x509.PublicKeyAlgorithm) string {
	switch {
	case p == x509.RSA:
		return "RSA"
	case p == x509.DSA:
		return "DSA"
	case p == x509.ECDSA:
		return "ECDSA"
	}

	return "UNKNOWN"
}

func validateRequest(req *http.Request) error {
	if req.URL == nil {
		return errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		return errors.New("http: nil Request.Header")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return errors.New("http: unsupported protocol scheme")
	}
	if req.URL.Host == "" {
		return errors.New("http: no Host in request URL")
	}

	return nil
}
