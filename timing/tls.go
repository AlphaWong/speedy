package timing

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
)

func addTLSInfo(req *http.Request, res *timingResults, log *logrus.Entry) {
	res.IsHTTPS = false
	if req.URL.Scheme == "https" {
		ips, err := net.LookupIP(req.URL.Host)
		if err != nil {
			log.WithError(err).Warn("Failed to resolve %s to an IP", req.URL.Host)
		}
		log.Debugf("Resolved %s to %v", req.URL.Host, ips)
		ip := ips[0].String()
		res.RawIP = ip
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:443", ip))
		if err != nil {
			log.WithError(err).Warnf("Failed to connect to %s", ip)
			return
		}

		res.IsHTTPS = true
		preTLS := time.Now()
		tconn := tls.Client(conn, &tls.Config{ServerName: req.URL.Host})
		tlsConn := (*tls.Conn)(tconn)
		if err = tlsConn.Handshake(); err != nil {
			res.ErrorCode = "failed_tls_handshake"
			res.ErrorMsg = err.Error()
			return
		}

		if err = tlsConn.VerifyHostname(req.URL.Host); err != nil {
			res.ErrorCode = "failed_hostname_validation"
			res.ErrorMsg = err.Error()
			return
		}

		state := tlsConn.ConnectionState()
		res.CipherSuite = convertCipher(state.CipherSuite)
		res.Protocols = state.NegotiatedProtocol
		res.CertificateAlgs = extractCertChain(&state)

		res.TLSHandshake = time.Since(preTLS)
	}
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
