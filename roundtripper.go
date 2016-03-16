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
	"os"
	"strings"
	"time"
)

func main() {
	url := os.Args[1]
	trans, err := roundTrip(url)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Time DNS: %s\n", trans.dnsResolve)
	fmt.Printf("Time First Byte: %s\n", trans.firstByte)
	fmt.Printf("Time Complete Load: %s\n", trans.completeLoad)
	fmt.Printf("Time Connecting: %s\n", trans.connect)
	fmt.Printf("Time Doing TLS Handshake: %s\n", trans.tlsHandshake)
	fmt.Printf("Time Writing Request: %s\n", trans.writeTime)

	fmt.Printf("Cipher Suite: %s\n", trans.cipherSuite)
	fmt.Printf("TLS Protocol: %s\n", trans.protocols)
	fmt.Printf("Algorithms: %+v\n", trans.certAlgorithms)
}

type certAlgPair struct {
	publicKeyAlgorithm string
	signatureAlgorithm string
}

type timingTransport struct {
	dnsResolve   time.Duration
	firstByte    time.Duration
	completeLoad time.Duration
	connect      time.Duration
	tlsHandshake time.Duration
	writeTime    time.Duration

	cipherSuite    string
	protocols      string
	certAlgorithms map[string]certAlgPair

	rsp *http.Response
}

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

func roundTrip(url string) (*timingTransport, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	res := new(timingTransport)

	err = validateRequest(req)
	if err != nil {
		return nil, err
	}

	conn, err := res.dial(req)
	if err != nil {
		return nil, err
	}

	client := httputil.NewClientConn(conn, nil)
	preWrite := time.Now()
	client.Write(req)
	postWrite := time.Now()
	res.writeTime = postWrite.Sub(preWrite)

	// discard the results, this should just read the first chunk from the sock
	client.Read(req)
	res.firstByte = time.Now().Sub(postWrite)

	// now just do a normal request
	preNormal := time.Now()
	res.rsp, err = http.Get(url)
	res.completeLoad = time.Now().Sub(preNormal)

	return res, nil
}

func extractCertChain(state *tls.ConnectionState) map[string]certAlgPair {
	results := make(map[string]certAlgPair)

	for _, cert := range state.PeerCertificates {
		results[cert.Issuer.CommonName] = certAlgPair{
			publicKeyAlgorithm: convertAlgorithm(cert.PublicKeyAlgorithm),
			signatureAlgorithm: cert.SignatureAlgorithm.String(),
		}
	}

	return results
}

func (t *timingTransport) dial(req *http.Request) (net.Conn, error) {
	host, port := canonicalize(req.URL)

	// host -> ip
	preDNS := time.Now()
	ips, err := net.LookupIP(host)
	t.dnsResolve = time.Now().Sub(preDNS)
	if err != nil {
		panic(err)
	}
	ip := ips[0]
	fmt.Printf("resolved %s -> %s\n", req.URL, ip)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", ip, port))
	if err != nil {
		return nil, err
	}

	if req.URL.Scheme == "https" {
		preTLS := time.Now()
		conn = tls.Client(conn, &tls.Config{ServerName: req.URL.Host})

		if err = conn.(*tls.Conn).Handshake(); err != nil {
			return nil, err
		}

		if err = conn.(*tls.Conn).VerifyHostname(req.URL.Host); err != nil {
			return nil, err
		}
		state := conn.(*tls.Conn).ConnectionState()
		t.cipherSuite = convertCipher(state.CipherSuite)
		t.protocols = state.NegotiatedProtocol
		t.certAlgorithms = extractCertChain(&state)

		t.tlsHandshake = time.Now().Sub(preTLS)
	}

	return conn, nil
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
