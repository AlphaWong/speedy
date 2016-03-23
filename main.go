package main

import (
	"encoding/json"
	"flag"
	"fmt"

	rc "github.com/netlify/rabbit-client"
	"github.com/streadway/amqp"
)

type expectedMessage struct {
	URL         string `json:"url"`
	CallbackURL string `json:"callback_url"`
	TimeoutSec  int32  `json:"timeout_sec"`
}

func main() {
	useCmdLine := flag.Bool(
		"cmdline",
		false,
		"if you want to use the commandline for the URL")
	showProgress := flag.Bool(
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
		processOneToCmdline(cmdLineVal, *showProgress)
	} else {
		if len(flag.Args()) != 1 {
			panic(fmt.Errorf("Must provide a filename\n"))
		}

		listenToRabbits(cmdLineVal)
	}
}

// just dump the values to the cmdline
func processOneToCmdline(url string, verbose bool) {
	results, err := roundtrip(url, verbose)
	if err != nil {
		panic(err)
	}

	bytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bytes))
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
				panic(err)
			}

			results, err := roundtrip(msg.URL, true)
			if err != nil {
				// don't panic here - just fail this one
				fmt.Printf("error while processing '%s': %v", msg.URL, err)

				// send it back?
			}

			fmt.Println(results)
		}(&delivery)
	}
}
