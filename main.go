package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	httpc "github.com/vislee/go-httppc"
)

var (
	ver        = "2.00"
	addr       = flag.String("addr", "", "Spec service listen addr. 'IP:port'")
	vmHostAddr = flag.String("vmHostAddr", "127.0.0.1", "The proxy protol vm host addr. 'IP[:port]'")
	cliAddr    = flag.String("cliAddr", "127.0.0.1", "The proxy protol client addr. 'IP'")
	testPlay   = flag.String("case", "./conf/case.json", "Test play case")
	proxyAddr  = flag.String("proxyAddr", "", "The proxy model listen addr. '[IP]:port'")
	ppEnable   = flag.Bool("PPEnable", false, "The proxy protocol enable. true or false")
	genCase    = flag.Bool("genCase", false, "Generate test case. true or false")
	ruledir    = flag.String("ruledir", "./rules", "sec rules dir path")
)

type matchKV struct {
	Key string `json:"key"`
	Typ string `json:"type"`
	Val string `json:"value"`
}

func (self *matchKV) Match(v string) (bool, string) {
	msg := fmt.Sprintf("\033[34m%s: got '%s', expected: '%s'\033[0m", self.Key, v, self.Val)

	if (self.Val == "" || len(self.Val) == 0) && (self.Typ == "" || len(self.Typ) == 0) {
		return true, msg
	}

	if self.Typ == "contain" {
		return strings.Contains(v, self.Val), msg

	} else if self.Typ == "regex" {
		rp, err := regexp.Compile(self.Val)
		if err != nil {
			log.Fatalln(err.Error())
			return false, msg
		}

		return rp.Match([]byte(v)), msg
	}

	return self.Val == v, msg
}

type Case struct {
	Title  string   `json:"title"`
	Delay  int64    `json:"delay"`
	Repeat uint     `json:"repeat"`
	Req    request  `json:"req"`
	Resp   response `json:"resp"`
}

type HttpCli interface {
	Do(req *http.Request) (*http.Response, error)
	SetTimeout(d time.Duration)
	// SetProxyProClientIP(remoteAddr string)
}

func (self *Case) Play(cli HttpCli, addr string) bool {
	var times uint = 0
	res := true

	time.Sleep(time.Duration(self.Delay) * time.Second)

	log.Printf("====[Title:%s][repeat:%d]====\n", self.Title, self.Repeat)

	req, err := self.Req.newRequest(addr)
	if err != nil {
		log.Println(err.Error())
		res = false
		goto endl
	} else {
		msgReq, _ := httputil.DumpRequest(req, false)
		log.Printf("Exec Req: \n%s", msgReq)
	}

	cli.SetTimeout(time.Duration(self.Req.Timeout))

	// cli.SetProxyProClientIP("127.0.0.1")
	// if len(self.Req.Addr) > 0 {
	// 	cli.SetProxyProClientIP(self.Req.Addr)
	// }

	for {
		resp, err := cli.Do(req)
		if err != nil {
			log.Println(err.Error())
			res = false
			goto endl
		}
		if !self.Resp.Match(resp) {
			res = false
			goto endl
		}

		times = times + 1
		if times > self.Repeat {
			break
		}
	}

endl:
	ok := "OK"
	if !res {
		ok = "\033[33m\033[01m\033[05mFail\033[0m"
	}
	log.Printf("====[%s]====\n\n", ok)

	return res
}

type cc struct {
	http.Client
}

func NewClient() *cc {
	return &cc{
		http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 90 * time.Second,
		},
	}
}

func (self *cc) SetTimeout(d time.Duration) {
	self.Client.Timeout = d * time.Second
}

type TestCases []Case

func casePlay() {
	ts := make([]Case, 0)
	if *testPlay != "" {
		data, err := ioutil.ReadFile(*testPlay)
		if err != nil {
			log.Println("read file err: ", err.Error())
			return
		}
		var t TestCases
		err = json.Unmarshal(data, &t)
		if err != nil {
			log.Println("unmarshal err: ", err.Error())
			return
		}
		ts = append(ts, t...)
	} else {
		files, err := ioutil.ReadDir("./conf")
		if err != nil {
			log.Println("read dir err: ", err.Error())
			return
		}
		for _, f := range files {
			//获取文件路径
			file := filepath.Join("./conf", f.Name())
			if strings.HasSuffix(file, ".json") {
				data, err := ioutil.ReadFile(file)
				if err != nil {
					//打印日志带行号
					log.Println("read file err: ", err.Error())
					return
				}
				var t TestCases
				err = json.Unmarshal(data, &t)
				if err != nil {
					log.Println("unmarshal err: ", err.Error())
					return
				}
				ts = append(ts, t...)
			}
		}
	}

	var cli HttpCli
	if *ppEnable {
		pc := httpc.NewProxyProClient()
		pc.NotFollowRedirects()
		pc.SetProxyProServerIP(*vmHostAddr)
		pc.SetProxyProClientIP(*cliAddr)
		cli = pc
	} else {
		cli = NewClient()
	}

	var x, y int = 0, 0
	caseId := make([]string, 0)
	failCase := make([]Case, 0)
	start := time.Now()
	for _, c := range ts {
		y = y + 1
		if !c.Play(cli, *addr) {
			caseId = append(caseId, c.Title)
			failCase = append(failCase, c)
			x = x + 1
		}
	}

	fmt.Println("\033[35m==============RESULT=================\033[0m")
	dura := time.Now().Sub(start)
	fmt.Printf("\033[32mFail=%d, Cases=%d, %v\033[0m\n", x, y, dura)
	if x > 0 {
		fmt.Println("Result: \033[31m\033[01m\033[05mFAIL\033[0m")
	} else {
		fmt.Println("Result: \033[32mPASS\033[0m")
	}
	fmt.Println("Fail Case: [")
	if len(caseId) > 0 {
		for _, id := range caseId {
			fmt.Printf("\t%s\n", id)
		}
	}

	if len(failCase) > 0 {
		data, _ := json.MarshalIndent(failCase, "", "    ")
		ioutil.WriteFile("fail_case.json", data, 0644)
	}
	fmt.Println("]")
	fmt.Println("\033[35m=====================================\033[0m")
	return
}

func proxyCopy(errc chan<- error, dst io.Writer, src io.Reader) {
	_, err := io.Copy(dst, src)

	errc <- err
}

func proxy_handler(conn net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

	var dial net.Dialer
	// upsconn, err := dial.DialContext(ctx, "tcp", "127.0.0.1:8083")
	upsconn, err := dial.DialContext(ctx, "tcp", *addr)

	if cancel != nil {
		cancel()
	}

	if err != nil {
		conn.Write([]byte("ups error: " + err.Error()))
		conn.Close()
		return
	}

	defer conn.Close()
	defer upsconn.Close()

	srvport := strings.SplitN(*addr, ":", 2)[1]
	cliport := strings.SplitN(conn.RemoteAddr().String(), ":", 2)[1]

	s := *vmHostAddr
	if ss := strings.Split(s, ":"); len(ss) == 2 {
		s = ss[0]
		srvport = ss[1]
	}

	if *ppEnable {
		pp := fmt.Sprintf("PROXY TCP4 %s %s %s %s\r\n", *cliAddr, s, cliport, srvport)

		_, err = upsconn.Write([]byte(pp))
		if err != nil {
			conn.Write([]byte("proxy protol error:" + err.Error()))
			conn.Close()
			return
		}
	}

	errc := make(chan error, 1)

	go proxyCopy(errc, conn, upsconn)
	go proxyCopy(errc, upsconn, conn)

	<-errc
}

func proxy() {
	ln, err := net.Listen("tcp", *proxyAddr)
	if err != nil {
		log.Fatalln(err.Error())
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}

		d := time.Now().Add(10 * time.Second)
		conn.SetReadDeadline(d)
		go proxy_handler(conn)
	}
}

func caseExample() string {
	var e = make([]Case, 1, 1)
	e[0].Req.Headers = map[string]string{"": ""}
	e[0].Resp.Headers = make([]matchKV, 1, 1)
	e[0].Resp.Cookies = make([]matchKV, 1, 1)

	es, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		log.Println(err.Error())
		return ""
	}

	return string(es)
}

/*
//
// ./testCaseWaf  -addr=10.110.26.8:8000 -case=./conf/202303_testcase.json
// ./testCaseWaf  -genCase=true -case=./conf/202303_testcase.json
*/
func main() {
	flag.Parse()
	if len(*addr) == 0 {
		if *testPlay == "help" {
			fmt.Println("$ cat conf/case.json")
			fmt.Println(caseExample())
		} else {
			log.Println("Error: Not Spec addr")
		}
		return
	}

	if len(*proxyAddr) > 0 {
		proxy()
	} else {
		if *genCase {
			ParseRule(*ruledir)
			if err := GenCase(); err != nil {
				log.Println("GenCase err: ", err.Error())
			}
		} else {
			casePlay()
		}
	}
}

func init() {
	flag.CommandLine.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Name\n  %s - Play testcase or proxy tool (version:%s)\n", os.Args[0], ver)
		flag.Usage()
		fmt.Fprintf(flag.CommandLine.Output(), "Examples\n\t$ %s -addr=127.0.0.1:80 -vmHostAddr=127.0.0.1 -cliAddr=127.0.0.1 -case=test.json\n\t$ %s -addr=127.0.0.1:80 -vmHostAddr=127.0.0.1:8989 -cliAddr=127.0.0.1 -proxyAddr=:8080\n\t$ %s --case help\n", os.Args[0], os.Args[0], os.Args[0])
	}
}
