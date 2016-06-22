package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/nats-io/nats"
	"github.com/spf13/cobra"

	"github.com/netlify/messaging"
)

var configFile string

// RootCmd is where all the magic is
var RootCmd = cobra.Command{
	Use: "util",
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file to use")
}

func loadFromFile(configFile string, configStruct interface{}) error {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, configStruct)
	if err != nil {
		return err
	}

	return nil
}

func connect(configFile string) (*nats.Conn, error) {
	natsConfig := new(messaging.NatsConfig)
	err := loadFromFile(configFile, natsConfig)
	if err != nil {
		return nil, err
	}

	nc, err := messaging.ConnectToNats(natsConfig)
	if err != nil {
		return nil, err
	}
	return nc, nil
}

func configOrDie(c *cobra.Command) string {
	if configFile == "" {
		c.Help()
		os.Exit(1)
	}

	return configFile
}

func stringOrDie(c *cobra.Command, arg string) string {
	v, err := c.Flags().GetString(arg)
	if v == "" || err != nil {
		fmt.Printf("Missing required param '%s'\n", arg)
		c.Help()
		os.Exit(1)
	}

	return v
}

func zipArgs(c *cobra.Command, args []string, expectedArgs []string) map[string]string {
	if len(expectedArgs) > len(args) {
		fmt.Println("Not enough args provided. Expected: " + strings.Join(expectedArgs, " "))
		c.Help()
		os.Exit(1)
	}
	res := make(map[string]string)
	for i, arg := range expectedArgs {
		res[arg] = args[i]
	}

	return res
}
