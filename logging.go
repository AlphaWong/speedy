package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/netlify/messaging"
)

type logConfiguration struct {
	Level    string    `json:"log_level"`
	File     string    `json:"log_file"`
	HookConf *hookConf `json:"hook_conf"`
}

type hookConf struct {
	messaging.NatsConfig
	Subject string `json:"subject"`
}

func configureLogging(cfg logConfiguration) (*logrus.Entry, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	if cfg.File != "" {
		f, errOpen := os.OpenFile(cfg.File, os.O_RDWR|os.O_APPEND, 0660)
		if errOpen != nil {
			return nil, errOpen
		}
		logrus.SetOutput(bufio.NewWriter(f))
	}

	level, err := logrus.ParseLevel(strings.ToUpper(cfg.Level))
	if err != nil {
		return nil, err
	}
	logrus.SetLevel(level)

	if cfg.HookConf != nil {
		nc, err := messaging.ConnectToNats(&cfg.HookConf.NatsConfig)
		if err != nil {
			return nil, err
		}

		hook, err := messaging.NewNatsHook(nc, cfg.HookConf.Subject)
		if err != nil {
			return nil, err
		}

		logrus.AddHook(hook)
	}
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:    true,
		DisableTimestamp: false,
	})
	return logrus.StandardLogger().WithField("hostname", hostname), nil
}
