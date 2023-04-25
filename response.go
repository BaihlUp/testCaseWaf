package main

import (
	"io/ioutil"
	"log"
	"net/http"
)

type response struct {
	Status  matchKV   `json:"status"`
	Headers []matchKV `json:"headers"`
	Cookies []matchKV `json:"cookies"`
	Body    matchKV   `json:"body"`
}

func (self *response) Match(resp *http.Response) bool {
	res := true

	if len(self.Status.Key) == 0 {
		self.Status.Key = "status"
	}
	if ok, msg := self.Status.Match(resp.Status); !ok {
		log.Println(msg)
		res = false
	}

	// resp.Header
	for _, header := range self.Headers {
		var h string

		if header.Key == "set-cookie" || header.Key == "Set-Cookie" {
			for _, ck := range resp.Cookies() {
				if len(h) == 0 {
					h = ck.String()
				} else {
					h = h + ", " + ck.String()
				}
			}

		} else {
			h = resp.Header.Get(header.Key)
		}

		if ok, msg := header.Match(h); !ok {
			log.Println(msg)
			res = false
		}
	}

	// resp cookie
	if len(self.Cookies) > 0 {
		resp_cks := make(map[string]string, len(resp.Cookies()))
		for _, rck := range resp.Cookies() {
			resp_cks[rck.Name] = rck.Value
		}

		for _, ck := range self.Cookies {

			val, ok := resp_cks[ck.Key]
			if !ok {
				val = ""
			}

			if ok, msg := ck.Match(val); !ok {
				log.Println(msg)
				res = false
				break
			}
		}
	}

	// body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("got resp body error. %s\n", err.Error())
		res = false
	} else {
		resp.Body.Close()
	}

	if len(self.Body.Key) == 0 {
		self.Body.Key = "body"
	}
	if ok, msg := self.Body.Match(string(data)); !ok {
		log.Println(msg)
		res = false
	}

	return res
}
