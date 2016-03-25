package main

import (
	"encoding/json"
	"io/ioutil"
	"log"

	rc "github.com/netlify/rabbit-client"
)

type config struct {
	DataCenter        string               `json:"data_center"`
	AMQPConfiguration rc.AMQPConfiguration `json:"amqp_config"`
}

func load(filename string) (*config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := new(config)
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}
	log.Printf("Loaded config %s: %+v\n", filename, cfg)
	return cfg, err
}
