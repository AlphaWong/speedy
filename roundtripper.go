package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

func (r *requestContext) measure() {
	res := new(timingResults)
	r.results = res
	res.IsHTTPS = strings.HasPrefix(r.url, "https")
	res.URL = r.url

	r.logger.Info("Starting Timing")

	req, err := http.NewRequest("GET", r.url, nil)
	if err != nil {
		r.logger.WithError(err).Warn("Failed to build request")
		return
	}

	r.logger.Info("Validating request")
	err = validateRequest(req)
	if err != nil {
		r.logger.WithError(err).Warn("Failed to validate request")
		return
	}
	r.logger.Info("Request is valid")

	// now just do a normal request
	r.logger.Info("Making full GET request")

	preNormal := time.Now()
	res.rsp, err = client.Do(req)
	if err != nil {
		errorCode := "failed_initial_request"
		if strings.Contains(err.Error(), "x509") {
			errorCode = "bad_certificates"
		} else if strings.Contains(err.Error(), "no such host") {
			errorCode = "no_such_host"
		}

		res.ErrorCode = errorCode
		res.ErrorMsg = err.Error()
		r.logger.WithError(err).Warn("Failed to make full request")
		return
	}
	res.CompleteLoad = time.Now().Sub(preNormal)

	res.IsHTTP2 = res.rsp.ProtoMajor == 2
	r.logger.Infof("Completed GET request in %s", res.CompleteLoad)

	defer res.rsp.Body.Close()

	body, err := ioutil.ReadAll(res.rsp.Body)
	if err != nil {
		res.ErrorCode = "failed_to_read_request_body"
		res.ErrorMsg = err.Error()
		r.logger.WithError(err).Warn("Failed to read request body")
		return
	}

	res.ContentSize = len(body)

	r.logger.Infof("Read request body of size %d", res.ContentSize)

	// now do the partials
	host, port := canonicalize(req.URL)

	r.logger.Info("Resolving DNS")
	rawip, err := resolve(host, res)
	if err != nil {
		res.ErrorCode = "failed_dns_resolve"
		res.ErrorMsg = err.Error()
		r.logger.WithError(err).Warnf("Failed to make resolve %s into an ip")
		return
	}

	r.logger.Infof("DNS successful: %s", rawip)

	directHost := formatURL(rawip, port)
	r.logger.Infof("Going to dial %s", directHost)
	conn, err := net.Dial("tcp", directHost)
	if err != nil {
		res.ErrorCode = "failed_to_connect"
		res.ErrorMsg = err.Error()
		r.logger.WithError(err).Warnf("Failed to dial")
		return
	}
	r.logger.Info("Finished dialing")

	r.logger.Info("Checking HTTPS certs")
	tryHTTPS(&conn, req, res)
	r.logger.Info("Finished HTTPS check")

	r.logger.Info("Checking time to first byte")
	client := httputil.NewClientConn(conn, nil)
	preWrite := time.Now()
	client.Write(req)
	postWrite := time.Now()
	res.WriteTime = postWrite.Sub(preWrite)
	r.logger.Info("Wrote request")
	// discard the results, this should just read the first chunk from the sock
	client.Read(req)
	res.FirstByte = time.Now().Sub(postWrite)
	r.logger.Info("Finished checking time to first byte")

	r.results = res
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

func formatURL(rawIP *net.IP, port string) string {
	var formattedIP string
	if ip := rawIP.To4(); ip != nil {
		formattedIP = fmt.Sprintf("%s:%s", rawIP, port)
	} else {
		formattedIP = fmt.Sprintf("[%s]:%s", rawIP, port)
	}
	return formattedIP
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

func resolve(host string, t *timingResults) (*net.IP, error) {
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

func tryHTTPS(conn *net.Conn, req *http.Request, t *timingResults) (tlsConn net.Conn, err error) {
	t.IsHTTPS = false
	if req.URL.Scheme == "https" {
		t.IsHTTPS = true
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
