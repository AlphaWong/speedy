package conf

import (
	"github.com/netlify/netlify-commons/messaging"
	"github.com/netlify/netlify-commons/nconf"
)

type Config struct {
	LogConf     nconf.LoggingConfig    `mapstructure:"log_conf"`
	NatsConf    *messaging.NatsConfig  `mapstructure:"nats_conf"`
	RabbitConf  messaging.RabbitConfig `mapstructure:"rabbit_conf"`
	MetricsConf *nconf.MetricsConfig   `mapstructure:"metrics_conf"`
	DataCenter  string                 `mapstructure:"data_center"`
}
