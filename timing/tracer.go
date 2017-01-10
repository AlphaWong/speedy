package timing

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/http2"
)

// This is what is needed but it breaks glide: https://github.com/netlify/speedy/issues/4
var http2Client = &http.Client{
	Transport: &http2.Transport{},
}
var httpClient = &http.Client{
	Transport: http.DefaultTransport,
}

func TimeRequest(r *requestContext) {
	res := new(timingResults)
	r.results = res
	res.OriginalURL = r.url

	//
	// validate request
	//
	r.logger.Info("Validating request")
	req, err := validateRequest(r.url)
	if err != nil {
		r.logger.WithError(err).Warn("Failed to validate request")
		return
	}
	r.logger.Info("Request is valid")

	//
	// redirect?
	//
	r.logger.Info("Checking for redirect")
	req, err = detectRedirect(req)
	if err != nil {
		r.logger.WithError(err).Warn("Failed to detect redirect")
		res.ErrorCode = "failed_redirect"
		res.ErrorMsg = err.Error()
		return
	}
	res.URL = req.URL.String()
	r.logger = r.logger.WithField("tested_url", res.URL)

	//
	// do a full request to make sure we can
	//
	madeAttempt := false
	if req.URL.Scheme == "https" {
		r.logger.Info("Attempting GET with the http2 client")
		err = fullTracedRequest(http2Client, req, res, r.logger.WithField("client", "http2"))
		if err != nil {
			r.logger.WithError(err).Info("Failed to make request - going to attempt over http")
			res.HTTP2Error = err.Error()
		} else {
			madeAttempt = true
		}
	}

	if !madeAttempt {
		r.logger.Info("Attempting GET with the http client")
		err = fullTracedRequest(httpClient, req, res, r.logger.WithField("client", "http"))
	}

	if err != nil {
		errorCode := "failed_initial_request"
		if strings.Contains(err.Error(), "x509") {
			errorCode = "bad_certificates"
		} else if strings.Contains(err.Error(), "no such host") {
			errorCode = "no_such_host"
		}

		res.ErrorCode = errorCode
		res.ErrorMsg = err.Error()
		r.logger.WithError(err).Warn("Failed to make full request, with both http2 and http")
	}

	r.logger.Infof("Completed GET request in %s", res.CompleteLoad)

	addTLSInfo(req, res, r.logger)
}

func fullTracedRequest(client *http.Client, req *http.Request, res *timingResults, log *logrus.Entry) error {
	var dnsStart time.Time
	var reqStart time.Time
	var connStart time.Time

	tracer := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			if info.Err != nil {
				res.ErrorCode = "failed_dns_resolve"
				res.ErrorMsg = info.Err.Error()
				log.WithError(info.Err).Warnf("Failed to make resolve DNS")
			}
			res.DNSResolve = time.Since(dnsStart)
		},
		GotFirstResponseByte: func() {
			res.FirstByte = time.Since(reqStart)
		},
		ConnectStart: func(network, addr string) {
			connStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			res.Connect = time.Since(connStart)
			if err != nil {
				res.ErrorCode = "failed_to_connect"
				res.ErrorMsg = err.Error()
				log.WithError(err).Warnf("Failed to dial %s", addr)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			res.Connect = time.Since(reqStart) - res.DNSResolve - res.Connect
			if info.Err != nil {
				res.ErrorCode = "failed_to_write_request"
				res.ErrorMsg = info.Err.Error()
				log.WithError(info.Err).Warnf("Failed to write request")
			}
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), tracer))
	reqStart = time.Now()
	rsp, err := client.Transport.RoundTrip(req)
	if err != nil {
		return err
	}

	// read in the response body
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		res.ErrorCode = "failed_to_read_request_body"
		res.ErrorMsg = err.Error()
		log.WithError(err).Warn("Failed to read request body")
		return err
	}
	res.CompleteLoad = time.Since(reqStart)

	// check for some headers
	res.IsNetlifySite = checkIfNetlifySite(rsp)
	res.IsHTTP2 = rsp.ProtoMajor == 2

	res.ContentSize = len(body)
	log.Infof("Read request body of size %d", res.ContentSize)

	return err
}

func detectRedirect(req *http.Request) (*http.Request, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// the final request that was made will be given in the response
	return resp.Request, nil
}

func checkIfNetlifySite(rsp *http.Response) bool {
	switch strings.ToLower(rsp.Header.Get("server")) {
	case "netlify":
		return true
	case "bitballoon":
		return true
	}
	return false
}

func validateRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if req.URL == nil {
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		return nil, errors.New("http: nil Request.Header")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, errors.New("http: unsupported protocol scheme")
	}
	if req.URL.Host == "" {
		return nil, errors.New("http: no Host in request URL")
	}

	return req, nil
}
