package cmd

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netlify/netlify-commons/messaging"
	"github.com/netlify/netlify-commons/metrics"
	"github.com/netlify/netlify-commons/nconf"

	"github.com/netlify/speedy/conf"
	"github.com/netlify/speedy/messages"
	"github.com/netlify/speedy/timing"
)

var rootCmd = &cobra.Command{
	Short: "speedy",
	Long:  "speedy",
	Run:   run,
}

func RootCmd() *cobra.Command {
	rootCmd.PersistentFlags().StringP("config", "c", "", "a config file to use")
	singleCmd.Flags().BoolP("verbose", "v", false, "if verbose logging is enabled")

	rootCmd.AddCommand(versionCmd, singleCmd)

	return rootCmd
}

func start(cmd *cobra.Command) (*conf.Config, *logrus.Entry) {
	config := new(conf.Config)
	if err := nconf.LoadConfig(cmd, "speedy", config); err != nil {
		logrus.WithError(err).Fatalf("Failed to load configuation: %v", err)
	}

	log, err := nconf.ConfigureLogging(&config.LogConf)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to configure logging")
	}

	log = log.WithFields(logrus.Fields{
		"data_center": config.DataCenter,
		"version":     Version,
	})

	if err := nconf.ConfigureMetrics(config.MetricsConf, log); err != nil {
		log.WithError(err).Fatal("Failed to configure metrics")
	}
	metrics.SetErrorHandler(logError(log))

	return config, log
}

func run(cmd *cobra.Command, _ []string) {
	config, log := start(cmd)

	if _, err := messaging.ConfigureNatsConnection(config.NatsConf, log); err != nil {
		log.WithError(err).Fatal("Failed to connect to nats")
	}

	consumer, err := messaging.ConnectToRabbit(&config.RabbitConf, log.WithField("stage", "connecting_rabbit"))
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to rabbits")
	}

	log.WithFields(logrus.Fields{
		"exchange":    config.RabbitConf.ExchangeDefinition.Name,
		"type":        config.RabbitConf.ExchangeDefinition.Type,
		"queue":       config.RabbitConf.QueueDefinition.Name,
		"binding_key": config.RabbitConf.QueueDefinition.BindingKey,
	}).Info("Starting to consume from channel")
	for d := range consumer.Deliveries {
		message := new(messages.Message)
		if err := json.Unmarshal(d.Body, &message); err != nil {
			log.WithError(err).Warnf("Failed to unmarshal: %s", d.Body)
			metrics.NewCounter("failed_parse", nil).Count(nil)
			continue
		}

		metrics.TimeBlock("request_duration", nil, func() {
			timing.ProcessRequest(message, config.DataCenter, log)
		})
		d.Ack(false)
	}
	log.Info("deliveries channel closed, shutting down")
}

func logError(log *logrus.Entry) func(*metrics.RawMetric, error) {
	return func(raw *metrics.RawMetric, err error) {
		log.WithError(err).WithField("component", "metric_errors").Errorf("Error while processing metric: %+v", *raw)
	}
}
