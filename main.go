package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	rc "github.com/netlify/rabbit-client"
	"github.com/streadway/amqp"
)

type expectedMessage struct {
	URL         string `json:"url"`
	CallbackURL string `json:"callback_url"`
	TimeoutSec  int32  `json:"timeout_sec"`
}

type resultPayload struct {
	Status  bool          `json:"status"`
	Results timingResults `json:"results"`
}

var client = &http.Client{}
var requestCounter int32

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

		listenToRabbits(cmdLineVal)
	}
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

// just dump the values to the cmdline
func processOneToCmdline(url string, verbose bool) {
	context := requestContext{
		url:    url,
		logger: getLogger(verbose, url),
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
func listenToRabbits(filename string) {
	config, err := load(filename)
	if err != nil {
		panic(err)
	}

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
				logger:       getLogger(true, msg.URL),
				requestIndex: atomic.AddInt32(&requestCounter, 1),
				url:          msg.URL,
			}

			context.measure()
			sendResponse(msg.CallbackURL, &context)
		}(&delivery)
	}
}

func sendResponse(url string, context *requestContext) {
	payload := resultPayload{
		Status: false,
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

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(asBytes))
	if err != nil {
		context.logger("Failed to build request to %s. error: %v", url, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	rsp, err := client.Do(req)
	if err != nil {
		context.logger("Failed to do response: %v", err)
		return
	}

	defer rsp.Body.Close()
	context.logger("Finished responding status is: %s", rsp.Status)
}
