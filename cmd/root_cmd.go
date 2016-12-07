package cmd

import (
	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"encoding/json"

	"github.com/netlify/speedy/conf"
	"github.com/netlify/speedy/messaging"
	"github.com/netlify/speedy/timing"
	"github.com/rybit/nats_metrics"
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
	config, err := conf.LoadConfig(cmd)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to load configuation: %v", err)
	}

	log, err := conf.ConfigureLogging(&config.LogConf)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to configure logging")
	}

	log = log.WithFields(logrus.Fields{
		"data_center": config.DataCenter,
		"version":     Version,
	})

	return config, log
}

func run(cmd *cobra.Command, _ []string) {
	config, log := start(cmd)
	messaging.Configure(config.NatsConf, log)

	deliveries, err := messaging.ConnectToRabbit(&config.RabbitConf, log.WithField("stage", "connecting_rabbit"))
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to rabbits")
	}

	log.WithFields(logrus.Fields{
		"exchange":    config.RabbitConf.ExchangeDefinition.Name,
		"type":        config.RabbitConf.ExchangeDefinition.Type,
		"queue":       config.RabbitConf.QueueDefinition.Name,
		"binding_key": config.RabbitConf.QueueDefinition.BindingKey,
	}).Info("Starting to consume from channel")
	for d := range deliveries {
		message := new(messaging.Message)
		if err := json.Unmarshal(d.Body, &message); err != nil {
			log.WithError(err).Warnf("Failed to unmarshal: %s", d.Body)
			metrics.NewCounter("speedy.failed_parse", nil).Count(nil)
			continue
		}

		metrics.TimeBlock("speedy.request_duration", nil, func() {
			timing.ProcessRequest(message, config.DataCenter, log)
		})
		d.Ack(false)
	}
	log.Info("deliveries channel closed, shutting down")
}
