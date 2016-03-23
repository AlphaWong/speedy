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
	flag.Parse()

	if *useCmdLine {
		if len(flag.Args()) != 1 {
			panic(fmt.Errorf("Must provide a URL\n"))
		}
		url := flag.Args()[0]
		results, err := roundtrip(url)
		if err != nil {
			panic(err)
		}

		fmt.Println(results)
	} else {
		if len(flag.Args()) != 1 {
			panic(fmt.Errorf("Must provide a filename\n"))
		}
		filename := flag.Args()[0]
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

				results, err := roundtrip(msg.URL)
				if err != nil {
					panic(err)
				}

				fmt.Println(results)
			}(&delivery)
		}
	}
}
