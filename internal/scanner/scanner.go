package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"testCaseWaf/internal/db"

	"testCaseWaf/internal/dnscache"

	"testCaseWaf/internal/config"
	"testCaseWaf/internal/openapi"
	"testCaseWaf/internal/payload/encoder"
)

const (
	preCheckVector        = "<script>alert('union select password from users')</script>"
	wsPreCheckReadTimeout = time.Second * 1
)

type testWork struct {
	caseName         string
	delay            int
	repeat           int
	setName          string
	caseID           string
	payload          string
	encoder          string
	placeholder      string
	testType         string
	isTruePositive   bool
	debugHeaderValue string

	Resp db.Resp
}

// Scanner allows you to test WAF in various ways with given payloads.
type Scanner struct {
	logger *logrus.Logger
	cfg    *config.Config
	db     *db.DB //保存测试例、测试结果

	httpClient *HTTPClient

	requestTemplates openapi.Templates
	router           routers.Router

	enableDebugHeader bool
}

// New creates a new Scanner.
func New(
	logger *logrus.Logger,
	cfg *config.Config,
	db *db.DB,
	dnsResolver *dnscache.Resolver,
	requestTemplates openapi.Templates,
	router routers.Router,
	enableDebugHeader bool,
) (*Scanner, error) {
	httpClient, err := NewHTTPClient(cfg, dnsResolver)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create HTTP client")
	}

	return &Scanner{
		logger:            logger,
		cfg:               cfg,
		db:                db,
		httpClient:        httpClient,
		requestTemplates:  requestTemplates,
		router:            router,
		enableDebugHeader: enableDebugHeader,
	}, nil
}

// Run starts a host scan to check WAF security.
func (s *Scanner) Run(ctx context.Context) error {
	gn := s.cfg.Workers
	var wg sync.WaitGroup
	wg.Add(gn)

	// rand.Seed(time.Now().UnixNano())
	s.logger.WithField("url", s.cfg.URL).Info("Scanning started")

	start := time.Now()
	defer func() {
		s.logger.WithField("duration", time.Since(start).String()).Info("Scanning finished")
	}()

	testChan := s.produceTests(ctx, gn)

	// 进度条
	// progressbarOptions := []progressbar.Option{
	// 	progressbar.OptionShowCount(),
	// 	progressbar.OptionSetPredictTime(false),
	// 	progressbar.OptionFullWidth(),
	// 	progressbar.OptionClearOnFinish(),
	// 	progressbar.OptionSetDescription("Sending requests..."),
	// 	progressbar.OptionSetTheme(progressbar.Theme{
	// 		Saucer:        "=",
	// 		SaucerHead:    ">",
	// 		SaucerPadding: " ",
	// 		BarStart:      "[",
	// 		BarEnd:        "]",
	// 	}),
	// }

	// // disable progress bar output if logging in JSONFormat
	// if _, ok := s.logger.Formatter.(*logrus.JSONFormatter); ok {
	// 	progressbarOptions = append(progressbarOptions, progressbar.OptionSetWriter(io.Discard))
	// }

	// bar := progressbar.NewOptions64(
	// 	int64(s.db.NumberOfTests),
	// 	progressbarOptions...,
	// )

	for e := 0; e < gn; e++ {
		go func(ctx context.Context) {
			defer wg.Done()
			for {
				select {
				case w, ok := <-testChan:
					if !ok {
						return
					}
					time.Sleep(time.Duration(w.delay) * time.Second)

					if err := s.scanURL(ctx, w); err != nil {
						s.logger.WithError(err).Error("Got an error while scanning")
					}

					// bar.Add(1)

				case <-ctx.Done():
					return
				}
			}
		}(ctx)
	}

	wg.Wait()
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}

	return nil
}

// checkBlocking checks the response status-code or request body using
// a regular expression to determine if the request has been blocked.
func (s *Scanner) checkBlocking(responseMsgHeader, body string, statusCode int) (bool, error) {
	if s.cfg.BlockRegex != "" {
		response := body
		if responseMsgHeader != "" {
			response = responseMsgHeader + body
		}

		if response != "" {
			m, _ := regexp.MatchString(s.cfg.BlockRegex, response)

			return m, nil
		}
	}

	for _, code := range s.cfg.BlockStatusCodes {
		if statusCode == code {
			return true, nil
		}
	}

	return false, nil
}

// checkPass checks the response status-code or request body using
// a regular expression to determine if the request has been passed.
func (s *Scanner) checkPass(responseMsgHeader, body string, statusCode int) (bool, error) {
	if s.cfg.PassRegex != "" {
		response := body
		if responseMsgHeader != "" {
			response = responseMsgHeader + body
		}

		if response != "" {
			m, _ := regexp.MatchString(s.cfg.BlockRegex, response)

			return m, nil
		}
	}

	for _, code := range s.cfg.PassStatusCodes {
		if statusCode == code {
			return true, nil
		}
	}

	return false, nil
}

// produceTests generates all combinations of payload, encoder, and placeholder
// for n goroutines.
func (s *Scanner) produceTests(ctx context.Context, n int) <-chan *testWork {
	testChan := make(chan *testWork, n)
	testCases := s.db.GetTestCases()

	go func() {
		defer close(testChan)

		var debugHeaderValue string

		hash := sha256.New()

		for _, testCase := range testCases {
			for _, payload := range testCase.Req.Payloads {
				for _, encoder := range testCase.Req.Encoders {
					for _, placeholder := range testCase.Req.Placeholders {
						if s.enableDebugHeader {
							hash.Reset()

							hash.Write([]byte(testCase.SetName))
							hash.Write([]byte(testCase.CaseId))
							hash.Write([]byte(placeholder))
							hash.Write([]byte(encoder))
							hash.Write([]byte(payload))

							debugHeaderValue = hex.EncodeToString(hash.Sum(nil))
						} else {
							debugHeaderValue = ""
						}

						wrk := &testWork{
							caseName:         testCase.Title,
							delay:            testCase.Delay,
							repeat:           testCase.Repeat,
							setName:          testCase.SetName,
							caseID:           testCase.CaseId,
							payload:          payload,
							encoder:          encoder,
							placeholder:      placeholder,
							testType:         testCase.Type,
							isTruePositive:   testCase.IsTruePositive,
							debugHeaderValue: debugHeaderValue,
							Resp:             testCase.Resp,
						}

						select {
						case testChan <- wrk:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()

	return testChan
}

// scanURL scans the host with the given combination of payload, encoder and
// placeholder.
func (s *Scanner) scanURL(ctx context.Context, w *testWork) error {
	fmt.Printf("exec DetectType: [%s], CaseName: [%s], CaseId: [%s]\n", w.setName, w.caseName, w.caseID)
	defer fmt.Printf("\n")
	var (
		response      *http.Response
		respHeaders   http.Header
		respMsgHeader string
		respBody      string
		statusCode    int
		err           error
	)

	if s.requestTemplates == nil {
		response, _, respBody, _, err = s.httpClient.SendPayload(ctx, s.cfg.URL, w.placeholder, w.encoder, w.payload, w.debugHeaderValue)

		if !s.checkCase(&w.Resp, response, respBody) {
			return nil
		}

		// _, _, _, _, err = s.updateDB(ctx, w, nil, nil, nil, nil, nil,
		// 	statusCode, nil, respMsgHeader, respBody, err, "", false)

		return err
	}

	templates := s.requestTemplates[w.placeholder]

	encodedPayload, err := encoder.Apply(w.encoder, w.payload)
	if err != nil {
		return errors.Wrap(err, "encoding payload")
	}

	var passedTest *db.Info
	var blockedTest *db.Info
	var unresolvedTest *db.Info
	var failedTest *db.Info
	var additionalInfo string

	for _, template := range templates {
		req, err := template.CreateRequest(ctx, w.placeholder, encodedPayload)
		if err != nil {
			return errors.Wrap(err, "create request from template")
		}

		respHeaders, respMsgHeader, respBody, statusCode, err = s.httpClient.SendRequest(req, w.debugHeaderValue)

		additionalInfo = fmt.Sprintf("%s %s", template.Method, template.Path)

		passedTest, blockedTest, unresolvedTest, failedTest, err =
			s.updateDB(ctx, w, passedTest, blockedTest, unresolvedTest, failedTest,
				req, statusCode, respHeaders, respMsgHeader, respBody, err, additionalInfo, false)

		s.db.AddToScannedPaths(template.Method, template.Path)

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Scanner) checkCase(matchResp *db.Resp, resp *http.Response, respBody string) bool {
	res := true
	if matchResp.Status != resp.StatusCode {
		fmt.Printf("\033[31m%s: got '%d', expected: '%d' [FAILED] \033[0m \n", "Status", resp.StatusCode, matchResp.Status)
		res = false
	}

	for _, header := range matchResp.Headers {
		if ok, msg := header.Match(resp.Header.Get(header.Key)); !ok {
			fmt.Printf("CheckHeader: ")
			fmt.Println(msg)
			res = false
		}
	}

	if ok, msg := matchResp.Body.Match(respBody); !ok {
		fmt.Printf("CheckBody: ")
		fmt.Println(msg)
		res = false
	}

	if res {
		fmt.Printf("\033[32m%s: got '%d', expected: '%d' [SUCCESSD] \033[0m \n", "Status", resp.StatusCode, matchResp.Status)
	}
	return res
}

// updateDB updates the success of a query in the database.
func (s *Scanner) updateDB(
	ctx context.Context,
	w *testWork,
	passedTest *db.Info,
	blockedTest *db.Info,
	unresolvedTest *db.Info,
	failedTest *db.Info,
	req *http.Request,
	respStatusCode int,
	respHeaders http.Header,
	respMsgHeader string,
	respBody string,
	sendErr error,
	additionalInfo string,
	isGRPC bool,
) (
	updPassedTest *db.Info,
	updBlockedTest *db.Info,
	updUnresolvedTest *db.Info,
	updFailedTest *db.Info,
	err error,
) {
	updPassedTest = passedTest
	updBlockedTest = blockedTest
	updUnresolvedTest = unresolvedTest
	updFailedTest = failedTest

	info := w.toInfo(respStatusCode)

	var blockedByReset bool
	if sendErr != nil {
		if errors.Is(sendErr, io.EOF) || errors.Is(sendErr, syscall.ECONNRESET) {
			if s.cfg.BlockConnReset {
				blockedByReset = true
			} else {
				if updUnresolvedTest == nil {
					updUnresolvedTest = info
					s.db.UpdateNaTests(updUnresolvedTest, s.cfg.IgnoreUnresolved, s.cfg.NonBlockedAsPassed, w.isTruePositive)
				}
				if len(additionalInfo) != 0 {
					unresolvedTest.AdditionalInfo = append(unresolvedTest.AdditionalInfo, additionalInfo)
				}

				return
			}
		} else {
			if updFailedTest == nil {
				updFailedTest = info
				s.db.UpdateFailedTests(updFailedTest)
			}
			if len(additionalInfo) != 0 {
				updFailedTest.AdditionalInfo = append(updFailedTest.AdditionalInfo, sendErr.Error())
			}

			s.logger.WithError(sendErr).Error("send request failed")

			return
		}
	}

	var blocked, passed bool
	if blockedByReset {
		blocked = true
	} else {
		blocked, err = s.checkBlocking(respMsgHeader, respBody, respStatusCode)
		if err != nil {
			return nil, nil, nil, nil,
				errors.Wrap(err, "failed to check blocking")
		}

		passed, err = s.checkPass(respMsgHeader, respBody, respStatusCode)
		if err != nil {
			return nil, nil, nil, nil,
				errors.Wrap(err, "failed to check passed or not")
		}
	}

	if s.requestTemplates != nil && !isGRPC {
		route, pathParams, routeErr := s.router.FindRoute(req)
		if routeErr != nil {
			// split Method and url template
			additionalInfoParts := strings.Split(additionalInfo, " ")
			if len(additionalInfoParts) < 2 {
				return nil, nil, nil, nil,
					errors.Wrap(routeErr, "couldn't find request route")
			}

			req.URL.Path = additionalInfoParts[1]
			route, pathParams, routeErr = s.router.FindRoute(req)
			if routeErr != nil {
				return nil, nil, nil, nil,
					errors.Wrap(routeErr, "couldn't find request route")
			}
		}

		inputReuqestValidation := &openapi3filter.RequestValidationInput{
			Request:     req,
			PathParams:  pathParams,
			QueryParams: req.URL.Query(),
			Route:       route,
		}

		responseValidationInput := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: inputReuqestValidation,
			Status:                 respStatusCode,
			Header:                 respHeaders,
			Body:                   io.NopCloser(strings.NewReader(respBody)),
			Options: &openapi3filter.Options{
				IncludeResponseStatus: true,
			},
		}

		if validationErr := openapi3filter.ValidateResponse(ctx, responseValidationInput); validationErr == nil && !blocked {
			if updPassedTest == nil {
				updPassedTest = info
				s.db.UpdatePassedTests(updPassedTest)
			}
			if len(additionalInfo) != 0 {
				updPassedTest.AdditionalInfo = append(updPassedTest.AdditionalInfo, additionalInfo)
			}
		} else {
			if updBlockedTest == nil {
				updBlockedTest = info
				s.db.UpdateBlockedTests(updBlockedTest)
			}
			if len(additionalInfo) != 0 {
				updBlockedTest.AdditionalInfo = append(updBlockedTest.AdditionalInfo, additionalInfo)
			}
		}

		return
	}

	if (blocked && passed) || (!blocked && !passed) {
		if updUnresolvedTest == nil {
			updUnresolvedTest = info
			s.db.UpdateNaTests(updUnresolvedTest, s.cfg.IgnoreUnresolved, s.cfg.NonBlockedAsPassed, w.isTruePositive)
		}
		if len(additionalInfo) != 0 {
			unresolvedTest.AdditionalInfo = append(unresolvedTest.AdditionalInfo, additionalInfo)
		}
	} else {
		if blocked {
			if updBlockedTest == nil {
				updBlockedTest = info
				s.db.UpdateBlockedTests(updBlockedTest)
			}
			if len(additionalInfo) != 0 {
				updBlockedTest.AdditionalInfo = append(updBlockedTest.AdditionalInfo, additionalInfo)
			}
		} else {
			if updPassedTest == nil {
				updPassedTest = info
				s.db.UpdatePassedTests(updPassedTest)
			}
			if len(additionalInfo) != 0 {
				updPassedTest.AdditionalInfo = append(updPassedTest.AdditionalInfo, additionalInfo)
			}
		}
	}

	return
}

func (w *testWork) toInfo(respStatusCode int) *db.Info {
	return &db.Info{
		Set:                w.setName,
		Case:               w.caseName,
		Payload:            w.payload,
		Encoder:            w.encoder,
		Placeholder:        w.placeholder,
		ResponseStatusCode: respStatusCode,
		Type:               w.testType,
	}
}
