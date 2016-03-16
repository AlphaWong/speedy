# speedy
A simple tool for testing the load times of a site.

## Usage
You can either provide a config file like
``` json
{
  "url": "",
  "exchange": "perftest",
  "queue": "incoming",
  "tls_config": {
    "cert": "",
    "key": "",
    "ca_cert": ""
  }
}
```

OR use the command line: `go run *.go -cmdline http[s]://netlify.com`
