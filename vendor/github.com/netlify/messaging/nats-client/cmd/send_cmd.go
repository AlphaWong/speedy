package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var sendFile string
var times int
var delaySendMs int

// SendCmd will read a file specified and send it to the subject/group specified
var SendCmd = cobra.Command{
	Use:   "send",
	Short: "send <subject> [ data ]",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfgFile := configOrDie(cmd)
		if len(args) == 0 {
			return errors.New("Require a subject")
		}
		subject := args[0]

		var data []byte
		var err error
		if sendFile == "" {
			if len(args) < 2 {
				return errors.New("must provide some data to send")
			}
			data = []byte(strings.Join(args[1:], " "))
		} else {
			data, err = ioutil.ReadFile(sendFile)
			if err != nil {
				return err
			}
		}

		return send(cfgFile, subject, data, times)
	},
}

func init() {
	SendCmd.Flags().StringVarP(&sendFile, "file", "f", "", "A file to read and send")
	SendCmd.Flags().IntVarP(&times, "times", "t", 1, "The number of times to send the message")
	SendCmd.Flags().IntVarP(&delaySendMs, "delay", "d", 0, "how long (in MS) to pause between writes")
}

func send(cfgFile, subject string, data []byte, times int) error {
	nc, err := connect(cfgFile)
	if err != nil {
		return err
	}

	for i := 0; i < times; i++ {
		fmt.Printf("%d/%d: Sending %d bytes of data to %s\n", i+1, times, len(data), subject)
		err = nc.Publish(subject, data)
		if err != nil {
			return err
		}
		err = nc.Flush()
		if err != nil {
			return err
		}

		if delaySendMs > 0 {
			fmt.Printf("sleeping for %d ms....", delaySendMs)
			time.Sleep(time.Duration(delaySendMs) * time.Millisecond)
			fmt.Println("awake")
		}
	}

	fmt.Println("completed")
	return nil
}
