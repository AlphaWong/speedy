package main

import (
	"encoding/json"
	"io/ioutil"

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

	return cfg, err
}
