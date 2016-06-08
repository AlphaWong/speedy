package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/netlify/messaging"
)

type config struct {
	DataCenter string           `json:"data_center"`
	LogConf    logConfiguration `json:"log_conf"`
	AMQPConf   rabbitConfig     `json:"amqp_config"`
}

type rabbitConfig struct {
	messaging.RabbitConfig
	Exchange messaging.ExchangeDefinition `json:"exchange"`
	Queue    messaging.QueueDefinition    `json:"queue"`
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
	return cfg, err
}
