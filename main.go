package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/labstack/gommon/log"
	"github.com/netlify/messaging"
	"github.com/spf13/cobra"
)

// what we should be sent via AMQP
type expectedMessage struct {
	URL         string `json:"url"`
	CallbackURL string `json:"callback_url"`
	TimeoutSec  int32  `json:"timeout_sec"`
	AuthToken   string `json:"auth_token"`
}

// what we will respond with via AMQP
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
	logger      *logrus.Entry
	url         string
	callbackURL string
	authToken   string
	timeoutSec  int32
	results     *timingResults
}

var requestCounter int32
var dataCenter string

func main() {

	var configFile string

	rootCmd := cobra.Command{
		Use:   "speedy",
		Short: "speedy will hook up to rabbitmq and then post the results back to the origin",
		Run: func(cmd *cobra.Command, args []string) {
			processForever(configFile)
		},
	}
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.json", "the config file to use")

	var enableDebug bool

	cmdLineCmd := cobra.Command{
		Use:   "single",
		Short: "single <url>",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				log.Fatal("Must provide a URL to search")
			}
			processOneToCmdline(args[0], enableDebug)
		},
	}
	cmdLineCmd.Flags().BoolVarP(&enableDebug, "verbose", "v", false, "if verbose logging is enabled")
	rootCmd.AddCommand(&cmdLineCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error running command: %s", err)
	}
}

// just dump the values to the cmdline
func processOneToCmdline(url string, verbose bool) {
	context := requestContext{
		url:    url,
		logger: logrus.StandardLogger().WithField("url", url),
	}

	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetOutput(ioutil.Discard)
		logrus.SetLevel(logrus.WarnLevel)
	}

	context.measure()
	if context.results != nil {
		bytes, err := json.MarshalIndent(context.results, "", "  ")
		if err != nil {
			panic(err)
		}

		fmt.Println(string(bytes))
	}
}

func processForever(configFile string) {
	config, err := load(configFile)
	if err != nil {
		log.Fatalf("Failed to load config file: %s - %s", configFile, err)
	}

	logger, err := configureLogging(config.LogConf)
	if err != nil {
		log.Fatalf("Failed to configure logging : %s", err)
	}

	dataCenter = config.DataCenter

	logger = logger.WithField("data_center", dataCenter)
	logger.Info("Starting speedy")

	rConf := config.AMQPConf

	// connect
	rc, err := messaging.ConnectToRabbit(&rConf.RabbitConfig)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to rabbits")
	}

	// bind
	c, q, err := messaging.Bind(rc, &rConf.Exchange, &rConf.Queue)
	if err != nil {
		logger.WithError(err).Fatal("Failed to bind to exchange/queue")
	}
	logger.WithFields(logrus.Fields{
		"exchange":    rConf.Exchange.Name,
		"queue":       rConf.Queue.Name,
		"binding_key": rConf.Queue.BindingKey,
	}).Info("Bound to exchange and queue")

	// consume
	deliveries, err := messaging.Consume(c, messaging.NewDeliveryDefinition(q.Name))
	if err != nil {
		logger.WithError(err).Fatal("Failed to get delivery channel")
	}

	logger.Info("Starting to consume incoming deliveries forever")

	for d := range deliveries {
		d.Ack(true) // can't do anything if we fail anyways

		msg := new(expectedMessage)
		if err := json.Unmarshal(d.Body, msg); err != nil {
			logger.WithError(err).Warn("Failed to unmarshal incoming request")
			continue
		}

		go processRequest(msg, logger)
	}
	logger.Warn("Exited - probably shouldn't have")
}

func processRequest(msg *expectedMessage, logger *logrus.Entry) {
	originalURL := msg.URL

	// now check for the other http
	var alternateURL string
	if strings.HasPrefix(msg.URL, "http") {
		alternateURL = "https" + msg.URL[4:]
	} else {
		alternateURL = "http" + msg.URL[5:]
	}

	requestID := rand.Int31()

	executeTest(&requestContext{
		url: originalURL,
		logger: logger.WithFields(logrus.Fields{
			"original_url": originalURL,
			"request_id":   requestID,
		}),
		callbackURL: msg.CallbackURL,
		authToken:   msg.AuthToken,
		timeoutSec:  msg.TimeoutSec,
	})
	executeTest(&requestContext{
		url: alternateURL,
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
		context.measure()
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
	dc := fmt.Sprintf("%s-http", dataCenter)
	if context.results.IsHTTPS {
		dc = fmt.Sprintf("%s-https", dataCenter)
	}
	errlog := context.logger.WithFields(logrus.Fields{
		"callback_url": context.callbackURL,
		"data_center":  dc,
	})

	payload := resultPayload{
		Status:     false,
		DataCenter: dc,
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
