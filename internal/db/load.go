package db

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"testCaseWaf/internal/config"
)

type matchKV struct {
	Key      string `json:"key",omitempty`
	Operator string `json:"operator"`
	Val      string `json:"value"`
}

type Request struct {
	Payloads     []string `yaml:"payload"`
	Encoders     []string `yaml:"encoder"`
	Placeholders []string `yaml:"placeholder"`
}

type Resp struct {
	Status  int       `yaml:"status"`
	Headers []matchKV `yaml:"headers"`
	Body    matchKV   `yaml:"body"`
}

type Case struct {
	Title          string  `yaml:"title"`
	Type           string  `default:"unknown" yaml:"type"`
	Delay          int     `yaml:"delay"`
	Repeat         int     `yaml:"repeat"`
	Req            Request `yaml:"req"`
	Resp           Resp    `yaml:"Resp"`
	Set            string
	Name           string
	IsTruePositive bool
}

func (self *matchKV) Match(v string) (bool, string) {
	msg := fmt.Sprintf("\033[34m%s: got '%s', expected: '%s'\033[0m", self.Key, v, self.Val)

	if (self.Val == "" || len(self.Val) == 0) && (self.Operator == "" || len(self.Operator) == 0) {
		return true, msg
	}

	if self.Operator == "contain" {
		return strings.Contains(v, self.Val), msg

	} else if self.Operator == "regex" {
		rp, err := regexp.Compile(self.Val)
		if err != nil {
			log.Fatalln(err.Error())
			return false, msg
		}

		return rp.Match([]byte(v)), msg
	}

	return self.Val == v, msg
}

func LoadTestCases(cfg *config.Config) (testCases []*Case, err error) {
	var files []string

	if cfg.TestCasesPath == "" {
		return nil, errors.New("empty test cases path")
	}

	if err = filepath.Walk(cfg.TestCasesPath, func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}

	for _, testCaseFile := range files {
		fileExt := filepath.Ext(testCaseFile)
		if fileExt != ".yml" && fileExt != ".yaml" {
			continue
		}

		// Ignore subdirectories, process as .../<testSetName>/<testCaseName>/<case>.yml
		parts := strings.Split(testCaseFile, string(os.PathSeparator))
		parts = parts[len(parts)-3:]

		testSetName := parts[1] //按攻击类型划分测试集合
		testCaseName := strings.TrimSuffix(parts[2], fileExt)

		if cfg.TestSet != "" && testSetName != cfg.TestSet {
			continue
		}

		if cfg.TestCase != "" && testCaseName != cfg.TestCase {
			continue
		}

		yamlFile, err := os.ReadFile(testCaseFile)
		if err != nil {
			return nil, err
		}

		var t Case
		err = yaml.Unmarshal(yamlFile, &t)
		if err != nil {
			return nil, err
		}

		t.Name = testCaseName
		t.Set = testSetName

		if strings.Contains(testSetName, "false") {
			t.IsTruePositive = false // test case is false positive
		} else {
			t.IsTruePositive = true // test case is true positive
		}

		testCases = append(testCases, &t)
	}

	if testCases == nil {
		return nil, errors.New("no tests were selected")
	}

	return testCases, nil
}
