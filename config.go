package main

import (
	"encoding/json"
	"io/ioutil"
	"log"

	rc "github.com/netlify/rabbit-client"
)

func load(filename string) (*rc.AMQPConfiguration, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := new(rc.AMQPConfiguration)
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}
	log.Printf("Loaded config %s: %+v\n", filename, cfg)
	return cfg, err
}
