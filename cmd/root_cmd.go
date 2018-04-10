package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nats-io/go-nats-streaming"
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
	work := make(chan []byte)
	shutdown := make(chan struct{})

	go doTimings(work, config.DataCenter, log)

	if config.NatsConf != nil {
		// ensure each worker has a different client id
		if inst := os.Getenv("SPEEDY_WORKER_INSTANCE"); inst != "" {
			config.NatsConf.ClientID = fmt.Sprintf("%s-%s", config.NatsConf.ClientID, inst)
		}
		nc, err := messaging.ConfigureNatsStreaming(&config.NatsConf.NatsConfig, log)
		if err != nil {
			log.WithError(err).Fatal("Failed to connect to nats")
		}
		go consumeFromNats(nc, config.NatsConf, work, shutdown, log.WithField("consumer", "nats"))
	}

	if config.RabbitConf != nil {
		go consumeFromRabbit(config.RabbitConf, work, shutdown, log.WithField("consumer", "rabbitmq"))
	}

	if config.NatsConf == nil && config.RabbitConf == nil {
		log.Fatal("No consumers configured")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-c

	close(shutdown)
	close(work)
}

func consumeFromNats(conn stan.Conn, conf *conf.NatsConfig, work chan<- []byte, shutdown chan struct{}, log *logrus.Entry) {
	if conn == nil {
		return
	}

	log = log.WithFields(logrus.Fields{
		"subject":      conf.Subject,
		"durable_name": conf.DurableName,
		"group":        conf.Group,
	})
	log.Info("Preparing durable subscription")

	opts := []stan.SubscriptionOption{
		stan.DurableName(conf.DurableName),
	}

	cb := func(msg *stan.Msg) {
		work <- msg.Data
	}

	var serr error
	var sub stan.Subscription
	if conf.Group != "" {
		sub, serr = conn.QueueSubscribe(conf.Subject, conf.Group, cb, opts...)
	} else {
		sub, serr = conn.Subscribe(conf.Subject, cb, opts...)
	}

	if serr != nil {
		log.WithError(serr).Fatal("Failed to subscribe")
		return
	}
	log.Info("Subscribed successfully")

	defer sub.Close()
	log.Info("Waiting for incoming messages")
	<-shutdown
	log.Info("Shutdown consumer")
}

func consumeFromRabbit(qc *messaging.RabbitConfig, work chan<- []byte, shutdown chan struct{}, log *logrus.Entry) {
	if err := messaging.ValidateRabbitConfigStruct(qc.Servers, qc.ExchangeDefinition, qc.QueueDefinition); err != nil {
		log.WithError(err).Fatal("Failed to configure rabbitmq")
	}

	rbConn, err := messaging.DialToRabbit(qc.Servers, qc.TLS, log)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to rabbitmq")
	}
	defer rbConn.Close()

	ch, err := messaging.CreateChannel(rbConn, qc.ExchangeDefinition, qc.QueueDefinition, log)
	if err != nil {
		log.WithError(err).Fatal("Failed to create rabbitmq channel")
	}
	if err = ch.Qos(1, 0, false); err != nil {
		log.WithError(err).Fatal("Failed to set QoS on rabbitmq channel")
	}

	consumer, err := messaging.CreateConsumerOnChannel(rbConn, ch, qc.QueueDefinition, qc.DeliveryDefinition, log)
	if err != nil {
		log.WithError(err).Fatal("Failed to create rabbitmq consumer")
	}

	log.WithFields(logrus.Fields{
		"exchange":    qc.ExchangeDefinition.Name,
		"type":        qc.ExchangeDefinition.Type,
		"queue":       qc.QueueDefinition.Name,
		"binding_key": qc.QueueDefinition.BindingKey,
	}).Info("Starting to consume from channel")
	for {
		select {
		case d, ok := <-consumer.Deliveries:
			if !ok {
				log.Info("deliveries channel closed, shutting down")
				syscall.Kill(os.Getpid(), syscall.SIGTERM)
				return
			}
			work <- d.Body
			d.Ack(false)
		case <-shutdown:
			return
		}
	}
}

func doTimings(work <-chan []byte, dc string, log *logrus.Entry) {
	for d := range work {
		message := new(messages.Message)
		if err := json.Unmarshal(d, &message); err != nil {
			log.WithError(err).Warnf("Failed to unmarshal: %s", d)
			metrics.NewCounter("failed_parse", nil).Count(nil)
			continue
		}

		metrics.TimeBlock("request_duration", nil, func() {
			timing.ProcessRequest(message, dc, log)
		})
	}
}

func logError(log *logrus.Entry) func(*metrics.RawMetric, error) {
	return func(raw *metrics.RawMetric, err error) {
		log.WithError(err).WithField("component", "metric_errors").Errorf("Error while processing metric: %+v", *raw)
	}
}
