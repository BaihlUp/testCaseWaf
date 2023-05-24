package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

type test struct {
	Uri    interface{} `json:"uri"`
	Method string      `json:"method"`
	Header interface{} `json:"header"`
	Body   string      `json:"body"`
}

type Rule struct {
	RuleName string                   `json:"rule_name"`
	Id       string                   `json:"id"`
	Match    []map[string]interface{} `json:"match"`
	Test     test                     `json:"test"`
}

var rule []Rule

func ParseRule(rd string) {
	files, err := ioutil.ReadDir(rd)
	if err != nil {
		log.Println("read dir err: ", err.Error())
		return
	}

	for _, f := range files {
		//获取文件路径
		file := filepath.Join(rd, f.Name())
		if strings.HasSuffix(file, ".json") {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				log.Printf("read file: %s err: %s", file, err.Error())
				continue
			}
			var r []Rule
			err = json.Unmarshal(data, &r)
			if err != nil {
				log.Printf("unmarshal file: %s err: %s", file, err.Error())
				continue
			}
			rule = append(rule, r...)
		}
	}
}

func GenCase() error {
	ca := make([]Case, 0)
	for _, r := range rule {
		var c Case
		c.Title = r.Id
		switch r.Test.Uri.(type) {
		case string:
			c.Req.Url = r.Test.Uri.(string)
		case []interface{}:
			c.Req.Url = r.Test.Uri.([]interface{})[0].(string)
		}
		switch r.Test.Header.(type) {
		case string:
			c.Req.Headers = map[string]string{"test": r.Test.Header.(string)}
		case map[string]string:
			c.Req.Headers = r.Test.Header.(map[string]string)
		}
		c.Req.Method = r.Test.Method
		c.Req.Body = r.Test.Body
		c.Req.Host = "192.168.170.150:9090"

		respStatus := matchKV{
			Key: "status",
			Typ: "contain",
			Val: "403",
		}
		respHeaders := matchKV{
			Key: "X-IWAF-Policyids",
			Typ: "contain",
			Val: r.Id,
		}
		respBody := matchKV{
			Key: "body",
			Typ: "regex",
			Val: "403 Forbidden",
		}
		c.Resp = response{
			Status:  respStatus,
			Headers: []matchKV{respHeaders},
			Body:    respBody,
		}
		ca = append(ca, c)
	}

	data, err := json.MarshalIndent(ca, "", "    ")
	if err != nil {
		log.Println("marshal err: ", err.Error())
		return err
	}

	err = ioutil.WriteFile("./testcase.json", data, 0644)
	if err != nil {
		log.Println("write file err: ", err.Error())
		return err
	}
	return nil
}
