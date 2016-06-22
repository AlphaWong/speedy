package messaging

import (
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/nats-io/nats"
)

// NatsConfig represents the minimum entries that are needed to connect to Nats over TLS
type NatsConfig struct {
	tlsDefinition

	Servers []string `json:"servers"`
}

// ServerString will build the proper string for nats connect
func (config *NatsConfig) ServerString() string {
	return strings.Join(config.Servers, ",")
}

// LogFields will return all the fields relevant to this config
func (config NatsConfig) LogFields() logrus.Fields {
	return logrus.Fields{
		"servers":   config.Servers,
		"ca_files":  config.CAFiles,
		"key_file":  config.KeyFile,
		"cert_file": config.CertFile,
	}
}

// ConnectToNats will do a TLS connection to the nats servers specified
func ConnectToNats(config *NatsConfig) (*nats.Conn, error) {
	tlsConfig, err := config.TLSConfig()
	if err != nil {
		return nil, err
	}

	return nats.Connect(config.ServerString(), nats.Secure(tlsConfig))
}
