# speedy
A simple tool for testing the load times of a site.

# Install
```sh
go get -u github.com/netlify/speedy
```

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

## Features
Speedy will:
- try and use the http2 client on any https url
  -  fallback to the http client if there is an error
- request both the http and https version of the site
- follow redirects and only time the final url in the redirect chain
