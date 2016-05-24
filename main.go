package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/streadway/amqp"

	"github.com/netlify/messaging"
)

var rootLogger = logrus.NewEntry(logrus.StandardLogger())

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
	DNSResolve   time.Duration `json:"dns_resolve"`
	FirstByte    time.Duration `json:"first_byte"`
	CompleteLoad time.Duration `json:"complete_load"`
	Connect      time.Duration `json:"connect"`
	TLSHandshake time.Duration `json:"tls_handshake"`
	WriteTime    time.Duration `json:"write_request"`
	ErrorMsg     string        `json:"error_msg"`
	ErrorCode    string        `json:"error_code"`
	URL          string        `json:"url"`
	ContentSize  int           `json:"content_size"`

	CipherSuite     string                 `json:"cipher_suite"`
	Protocols       string                 `json:"protocols"`
	CertificateAlgs map[string]certAlgPair `json:"certificate_algs"`
	IsHTTPS         bool                   `json:"is_https"`

	rsp *http.Response
}

type certAlgPair struct {
	PublicKeyAlgorithm string
	SignatureAlgorithm string
}

// used to contain a single request, makes logging and such nice
type requestContext struct {
	logger  *logrus.Entry
	url     string
	results *timingResults
}

var client = &http.Client{}
var requestCounter int32
var dataCenter string

func main() {
	var configFile string
	var verbose bool
	rootCmd := cobra.Command{
		Use:   "speedy",
		Short: "speedy will by default connect and listen for timing requests",
		Run: func(c *cobra.Command, args []string) {
			bindAndRun(configFile, verbose)
		},
	}
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.json", "the config to use")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "to enable more logging")

	// so we can call it from the command line
	singleQuery := cobra.Command{
		Use:   "query",
		Short: "query will execute a query using the url on the command line",
		Run: func(c *cobra.Command, args []string) {
			if len(args) != 1 {
				rootLogger.Fatal("Must provide a URL to query")
			}

			processOneToCmdline(args[0], verbose)
		},
	}
	rootCmd.AddCommand(&singleQuery)

	logrus.SetLevel(logrus.InfoLevel)
	err := rootCmd.Execute()
	if err != nil {
		rootLogger.WithError(err).Fatal("Failed to run speedy")
	}
}
func bindAndRun(configFile string, verbose bool) {
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	config, err := load(configFile)
	if err != nil {
		panic(err)
	}
	dataCenter = config.DataCenter
	rootLogger = rootLogger.WithField("datacenter", config.DataCenter)

	listenToRabbits(config)
}

// just dump the values to the cmdline
func processOneToCmdline(url string, verbose bool) {
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}

	context := requestContext{
		url:    url,
		logger: rootLogger,
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

// start listening forever to the rabbitmq server specified
func listenToRabbits(config *speedyConfig) {
	rabbitConfig := new(messaging.RabbitConfig)
	rabbitConfig.CertFile = config.AMQPConfig.TLSConfig.CertFile
	rabbitConfig.KeyFile = config.AMQPConfig.TLSConfig.KeyFile
	rabbitConfig.CAFiles = config.AMQPConfig.TLSConfig.CAFiles
	rabbitConfig.URL = config.AMQPConfig.URL

	rootLogger.WithFields(logrus.Fields{
		"url":       rabbitConfig.URL,
		"cert_file": rabbitConfig.CertFile,
		"ca_files":  rabbitConfig.CAFiles,
		"key_file":  rabbitConfig.KeyFile,
	}).Debug("Connecting to rabbitmq")

	conn, err := messaging.ConnectToRabbit(rabbitConfig)
	if err != nil {
		rootLogger.WithError(err).Fatal("Failed to connect to rabbits")
	}

	rootLogger.WithFields(logrus.Fields{
		"exchange":      config.AMQPConfig.Exchange.Name,
		"exchange_type": config.AMQPConfig.Exchange.Type,
		"queue":         config.AMQPConfig.Queue.Name,
		"binding_key":   config.AMQPConfig.Queue.BindingKey,
	}).Debug("binding to exchange and queue")
	c, _, err := messaging.Bind(conn, &config.AMQPConfig.Exchange, &config.AMQPConfig.Queue)
	if err != nil {
		rootLogger.WithError(err).Fatal("Failed to bind exchange and queue")
	}

	rootLogger.Debug("getting delivery channel")
	incomingDelivery, err := messaging.Consume(c, messaging.NewDeliveryDefinition(config.AMQPConfig.Queue.Name))
	if err != nil {
		rootLogger.WithError(err).Fatal("Failed to get delivery channel")
	}

	rootLogger.Debug("Consuming forever")
	for delivery := range incomingDelivery {
		go func(d *amqp.Delivery) {
			d.Ack(true) // can't do anything if we fail anyways

			msg := new(expectedMessage)
			if err = json.Unmarshal(d.Body, msg); err != nil {
				fmt.Printf("Failed to unmarshal body %s, %v\n", string(d.Body), err)
				return
			}

			originalURL := msg.URL

			// now check for the other http
			var alternateURL string
			if strings.HasPrefix(msg.URL, "http") {
				alternateURL = "https" + msg.URL[4:]
			} else {
				alternateURL = "http" + msg.URL[5:]
			}

			executeTest(originalURL, msg.CallbackURL, msg.AuthToken, msg.TimeoutSec)
			executeTest(alternateURL, msg.CallbackURL, msg.AuthToken, msg.TimeoutSec)

		}(&delivery)
	}
}

func executeTest(url, callback, token string, timeout int32) {
	context := requestContext{
		logger: rootLogger.WithFields(logrus.Fields{
			"url":           url,
			"request_count": atomic.AddInt32(&requestCounter, 1),
		}),
		url: url,
	}

	if token == "" {
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
		sendResponse(callback, token, &context)
	case <-time.After(time.Duration(timeout) * time.Second):
		context.logger.Warn("Timed out")
		context.results = nil

		sendResponse(callback, token, &context)
	}
}

func sendResponse(url string, authToken string, context *requestContext) {
	dc := fmt.Sprintf("%s-http", dataCenter)
	if context.results.IsHTTPS {
		dc = fmt.Sprintf("%s-https", dataCenter)
	}

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
		fmt.Printf("Failed to marshal payload to %s: %v. error: %v", url, payload, err)
		return
	}

	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(asBytes))
	if err != nil {
		context.logger.Errorf("Failed to build request to %s. error: %v", url, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", authToken)

	rsp, err := client.Do(req)
	if err != nil {
		context.logger.Errorf("Failed to do response: %v", err)
		return
	}

	defer rsp.Body.Close()
	context.logger.Infof("Finished responding status is: %s", rsp.Status)
}
