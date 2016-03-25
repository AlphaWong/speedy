package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	rc "github.com/netlify/rabbit-client"
	"github.com/streadway/amqp"
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

type certAlgPair struct {
	PublicKeyAlgorithm string
	SignatureAlgorithm string
}

// used to contain a single request, makes logging and such nice
type requestContext struct {
	logger       func(string, ...interface{})
	requestIndex int32
	url          string
	results      *timingResults
}

var client = &http.Client{}
var requestCounter int32
var dataCenter string

func main() {
	useCmdLine := flag.Bool(
		"cmdline",
		false,
		"if you want to use the commandline for the URL")
	verbose := flag.Bool(
		"verbose",
		false,
		"if you want step by step in the command line world",
	)
	flag.Parse()

	cmdLineVal := flag.Args()[0]
	if *useCmdLine {
		if len(flag.Args()) != 1 {
			panic(fmt.Errorf("Must provide a URL\n"))
		}

		processOneToCmdline(cmdLineVal, *verbose)
	} else {
		if len(flag.Args()) != 1 {
			panic(fmt.Errorf("Must provide a filename\n"))
		}

		config, err := load(cmdLineVal)
		if err != nil {
			panic(err)
		}
		dataCenter = config.DataCenter
		listenToRabbits(&config.AMQPConfiguration)
	}
}

func buildLogger(url string) func(string, ...interface{}) {
	return func(format string, args ...interface{}) {
		format = "%d - %s : " + format
		args = append([]interface{}{requestCounter, url}, args...)

		if !strings.HasSuffix(format, "\n") {
			format = format + "\n"
		}
		fmt.Printf(format, args...)
	}
}

var silentLogger = func(string, ...interface{}) {}

// just dump the values to the cmdline
func processOneToCmdline(url string, verbose bool) {
	context := requestContext{
		url:    url,
		logger: silentLogger,
	}

	if verbose {
		context.logger = buildLogger(url)
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
func listenToRabbits(config *rc.AMQPConfiguration) {
	incomingDelivery, err := rc.NewConsumer(config)
	if err != nil {
		panic(err)
	}

	for delivery := range incomingDelivery {
		go func(d *amqp.Delivery) {
			d.Ack(true) // can't do anything if we fail anyways

			msg := new(expectedMessage)
			if err = json.Unmarshal(d.Body, msg); err != nil {
				fmt.Printf("Failed to unmarshal body %s, %v\n", string(d.Body), err)
				return
			}

			// create the context around this message
			context := requestContext{
				logger:       buildLogger(msg.URL),
				requestIndex: atomic.AddInt32(&requestCounter, 1),
				url:          msg.URL,
			}

			if msg.AuthToken == "" {
				context.logger("No auth token provided")
				return
			}

			done := make(chan bool)
			go func() {
				context.measure()
				done <- true
			}()

			select {
			case <-done:
				sendResponse(msg.CallbackURL, msg.AuthToken, &context)
			case <-time.After(time.Duration(msg.TimeoutSec) * time.Second):
				context.logger("Timed out")
				context.results = nil

				sendResponse(msg.CallbackURL, msg.AuthToken, &context)
			}

		}(&delivery)
	}
}

func sendResponse(url string, authToken string, context *requestContext) {
	payload := resultPayload{
		Status:     false,
		DataCenter: dataCenter,
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
		context.logger("Failed to build request to %s. error: %v", url, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Token", authToken)

	rsp, err := client.Do(req)
	if err != nil {
		context.logger("Failed to do response: %v", err)
		return
	}

	defer rsp.Body.Close()
	context.logger("Finished responding status is: %s", rsp.Status)
}
