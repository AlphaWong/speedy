package timing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/netlify/speedy/messages"
	"github.com/sirupsen/logrus"
)

// what we will respond with
type resultPayload struct {
	Status     bool          `json:"status"`
	DataCenter string        `json:"data_center"`
	Results    timingResults `json:"results"`
}

type timingResults struct {
	DNSResolve    time.Duration `json:"dns_resolve"`
	FirstByte     time.Duration `json:"first_byte"`
	CompleteLoad  time.Duration `json:"complete_load"`
	Connect       time.Duration `json:"connect"`
	TLSHandshake  time.Duration `json:"tls_handshake"`
	WriteTime     time.Duration `json:"write_request"`
	HTTP2Error    string        `json:"http2_error"`
	ErrorMsg      string        `json:"error_msg"`
	ErrorCode     string        `json:"error_code"`
	OriginalURL   string        `json:"original_url"`
	URL           string        `json:"url"`
	ContentSize   int           `json:"content_size"`
	RawIP         string        `json:"raw_ip"`
	IsNetlifySite bool          `json:"is_netlify_site"`

	CipherSuite     string                 `json:"cipher_suite"`
	Protocols       string                 `json:"protocols"`
	CertificateAlgs map[string]certAlgPair `json:"certificate_algs"`
	IsHTTPS         bool                   `json:"is_https"`
	IsHTTP2         bool                   `json:"is_http_2"`

	rsp *http.Response
}

type certAlgPair struct {
	PublicKeyAlgorithm string
	SignatureAlgorithm string
}

// used to contain a single request, makes logging and such nice
type requestContext struct {
	ID          string
	DataCenter  string
	logger      *logrus.Entry
	url         string
	callbackURL string
	authToken   string
	timeoutSec  int32
	results     *timingResults
}

func ProcessRequest(msg *messages.Message, dc string, logger *logrus.Entry) {
	originalURL := msg.URL

	// now check for the other http
	var alternateURL string
	var originalDC string
	var alternateDC string
	if strings.HasPrefix(msg.URL, "https") {
		alternateURL = "http" + msg.URL[5:]
		originalDC = fmt.Sprintf("%s-https", dc)
		alternateDC = fmt.Sprintf("%s-http", dc)
	} else {
		originalDC = fmt.Sprintf("%s-http", dc)
		alternateDC = fmt.Sprintf("%s-https", dc)
		alternateURL = "https" + msg.URL[4:]
	}

	requestID := rand.Int31()

	executeTest(&requestContext{
		ID:  fmt.Sprintf("original-%s", time.Now().Nanosecond()),
		url: originalURL,
		logger: logger.WithFields(logrus.Fields{
			"original_url": originalURL,
			"request_id":   requestID,
		}),
		DataCenter:  originalDC,
		callbackURL: msg.CallbackURL,
		authToken:   msg.AuthToken,
		timeoutSec:  msg.TimeoutSec,
	})
	executeTest(&requestContext{
		ID:         fmt.Sprintf("alternate-%s", time.Now().Nanosecond()),
		url:        alternateURL,
		DataCenter: alternateDC,
		logger: logger.WithFields(logrus.Fields{
			"original_url": alternateURL,
			"request_id":   requestID,
		}),
		callbackURL: msg.CallbackURL,
		authToken:   msg.AuthToken,
		timeoutSec:  msg.TimeoutSec,
	})
}

func executeTest(context *requestContext) {
	if context.authToken == "" {
		context.logger.Warn("No auth token provided")
		return
	}

	done := make(chan bool)
	go func() {
		// Let sites with caching that just got deployed warm up for more realistic results
		TimeRequest(context)
		TimeRequest(context)

		TimeRequest(context)
		done <- true
	}()

	select {
	case <-done:
		sendResponse(context)
	case <-time.After(time.Duration(context.timeoutSec) * time.Second):
		context.logger.Warn("Timed out")
		context.results = nil

		sendResponse(context)
	}
}

func sendResponse(context *requestContext) {
	errlog := context.logger.WithFields(logrus.Fields{
		"callback_url": context.callbackURL,
	})

	payload := resultPayload{
		Status:     false,
		DataCenter: context.DataCenter,
	}

	if context.results != nil {
		payload.Status = true
		payload.Results = *context.results
	}

	asBytes, err := json.Marshal(&payload)
	if err != nil {
		errlog.WithError(err).Warnf("Failed to marshal payload.")
		return
	}

	req, err := http.NewRequest(http.MethodPatch, context.callbackURL, bytes.NewBuffer(asBytes))
	if err != nil {
		errlog.WithError(err).Warn("Failed to build request")
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", context.authToken)

	client := httpClient
	if req.URL.Scheme == "https" {
		client = http2Client
	}

	rsp, err := client.Do(req)
	if err != nil {
		errlog.WithError(err).Warn("Failed to do request")
		return
	}

	defer rsp.Body.Close()
	context.logger.WithField("status", rsp.Status).Infof("Finished responding status is: %s", rsp.Status)
}
