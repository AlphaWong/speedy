package cmd

import (
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	nats "github.com/nats-io/go-nats"
	"github.com/nats-io/go-nats-streaming"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netlify/netlify-commons/messaging"
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

func start(cmd *cobra.Command) (*conf.Config, *logrus.Entry, *statsd.Client) {
	config := new(conf.Config)
	if err := nconf.LoadConfig(cmd, "speedy", config); err != nil {
		logrus.WithError(err).Fatalf("Failed to load configuation: %v", err)
	}
	if config.NumWorkers < 1 {
		config.NumWorkers = 1
	}

	log, err := nconf.ConfigureLogging(&config.LogConf)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to configure logging")
	}

	log = log.WithFields(logrus.Fields{
		"data_center": config.DataCenter,
		"version":     Version,
	})

	sc, err := statsd.New("127.0.0.1:8125")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to configure metrics")
	}
	if config.MetricsConf != nil {
		sc.Namespace = config.MetricsConf.Namespace
		for k, v := range config.MetricsConf.Dimensions {
			sc.Tags = append(sc.Tags, k+":"+v)
		}
	}

	return config, log, sc
}

func run(cmd *cobra.Command, _ []string) {
	config, log, sc := start(cmd)
	work := make(chan []byte)
	shutdown := make(chan struct{})

	for i := 1; i <= config.NumWorkers; i++ {
		go doTimings(work, config.DataCenter, log.WithField("worker", i), sc)
	}

	if config.NatsConf != nil {
		nc, err := messaging.ConfigureNatsStreaming(&config.NatsConf.NatsConfig, log)
		if err != nil {
			log.WithError(err).Fatal("Failed to connect to nats")
		}
		rc := nc.NatsConn()
		rc.SetClosedHandler(func(c *nats.Conn) {
			log.Warn("NATS connection closed")
		})
		rc.SetDisconnectHandler(func(c *nats.Conn) {
			log.Warn("NATS connection disconnected")
		})
		rc.SetReconnectHandler(func(c *nats.Conn) {
			log.Warn("NATS reconnecting")
		})
		go consumeFromNats(nc, config.NatsConf, work, shutdown, log.WithField("consumer", "nats"))
	}

	if config.NatsConf == nil {
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

func doTimings(work <-chan []byte, dc string, log *logrus.Entry, sc *statsd.Client) {
	for d := range work {
		message := new(messages.Message)
		if err := json.Unmarshal(d, &message); err != nil {
			log.WithError(err).Warnf("Failed to unmarshal: %s", d)
			sc.Incr("failed_parse", nil, 1)
			continue
		}

		start := time.Now()
		timing.ProcessRequest(message, dc, log)
		sc.Timing("request_duration", time.Since(start), nil, 1)
	}
}
