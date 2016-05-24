package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/netlify/messaging"
)

type speedyConfig struct {
	DataCenter string     `json:"data_center"`
	AMQPConfig amqpConfig `json:"amqp_config"`
}

type amqpConfig struct {
	URL       string                       `json:"url"`
	Exchange  messaging.ExchangeDefinition `json:"exchange"`
	Queue     messaging.QueueDefinition    `json:"queue"`
	TLSConfig tlsConfig                    `json:"tls_config"`
}

type tlsConfig struct {
	CertFile string   `json:"cert"`
	KeyFile  string   `json:"key"`
	CAFiles  []string `json:"ca_certs"`
}

func load(filename string) (*speedyConfig, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := new(speedyConfig)
	err = json.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, err
}
