package main

import (
	"fmt"
	"net/http"
	"testCaseWaf/encoder"
	"testCaseWaf/placeholder"
)

type request struct {
	Timeout int64             `json:"timeout,omitempty"`
	Method  string            `json:"method"`
	Url     string            `json:"url"`
	Host    string            `json:"host"`
	Addr    string            `json:"realAddr,omitempty"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func (self *request) newRequest(addr string) (*http.Request, error) {
	// method := "GET"
	// var b *bytes.Buffer = bytes.NewBufferString("")

	self.Url, _ = encoder.Apply("URL", self.Url)
	targetUrl := fmt.Sprintf("http://%s", addr)
	if req, err := placeholder.Apply(targetUrl, "URLPath", self.Url); err != nil {
		return nil, err
	} else {
		req.Host = self.Host
		req.Method = self.Method

		for k, v := range self.Headers {
			req.Header.Add(k, v)
		}

		return req, nil
	}

	// url := fmt.Sprintf("http://%s%s", addr, self.Url)

	// if len(self.Body) > 0 {
	// 	method = "POST"
	// 	b = bytes.NewBufferString(self.Body)
	// }

	// if self.Method != "" {
	// 	method = self.Method
	// }

	// req, err := http.NewRequest(method, url, b)
	// if err != nil {
	// 	return req, err
	// }
}
