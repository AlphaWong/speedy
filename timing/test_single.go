package timing

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
)

// just dump the values to the cmdline
func ProcessSingle(url string) {
	context := &requestContext{
		url:    url,
		logger: logrus.StandardLogger().WithField("url", url),
	}

	TimeRequest(context)
	if context.results != nil {
		bytes, err := json.MarshalIndent(context.results, "", "  ")
		if err != nil {
			panic(err)
		}

		fmt.Println(string(bytes))
	}
}
