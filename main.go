package main

import (
	"flag"
	"fmt"

	rc "github.com/netlify/rabbit-client"
)

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

		incomingMessages, err := rc.Connect(config)
		if err != nil {
			panic(err)
		}

		for msg := range incomingMessages {
			url := msg.Payload
			results, err := roundtrip(url)
			if err != nil {
				panic(err)
			}
			fmt.Println(results)
		}
	}
}
