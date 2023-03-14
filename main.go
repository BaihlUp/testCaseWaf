package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"testCaseWaf/internal/db"

	"testCaseWaf/internal/scanner"

	"testCaseWaf/internal/openapi"

	"testCaseWaf/internal/version"
)

type MyFormatter struct{}

func (m *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	timestamp := entry.Time.Format("2006-01-02 15:04:05")
	var newLog string

	//HasCaller()为true才会有调用信息
	if entry.HasCaller() {
		fName := filepath.Base(entry.Caller.File)
		// newLog = fmt.Sprintf("[%s] [%s] [%s:%d %s] %s\n",
		// 	timestamp, entry.Level, fName, entry.Caller.Line, entry.Caller.Function, entry.Message)
		newLog = fmt.Sprintf("[%s] [%s] [%s:%d] %s\n",
			timestamp, entry.Level, fName, entry.Caller.Line, entry.Message)
	} else {
		newLog = fmt.Sprintf("[%s] [%s] %s\n", timestamp, entry.Level, entry.Message)
	}

	b.WriteString(newLog)
	return b.Bytes(), nil
}

func main() {
	logger := logrus.New()

	logger.SetReportCaller(true)
	logger.SetFormatter(&MyFormatter{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-shutdown
		logger.WithField("signal", sig).Info("scan canceled")
		cancel()
	}()

	if err := run(ctx, logger); err != nil {
		logger.WithError(err).Error("caught error in main function")
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *logrus.Logger) error {
	_, err := parseFlags()
	if err != nil {
		return err
	}

	if quiet {
		logger.SetOutput(io.Discard)
	}
	logger.SetLevel(logLevel)

	if logFormat == jsonLogFormat {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	cfg, err := loadConfig()
	if err != nil {
		return errors.Wrap(err, "couldn't load config")
	}

	logger.WithField("version", version.Version).Info("GoTestWAF started")

	var openapiDoc *openapi3.T
	var router routers.Router
	var templates openapi.Templates

	if cfg.OpenAPIFile != "" {
		openapiDoc, router, err = openapi.LoadOpenAPISpec(ctx, cfg.OpenAPIFile)
		if err != nil {
			return errors.Wrap(err, "couldn't load OpenAPI spec")
		}
		openapiDoc.Servers = append(openapiDoc.Servers, &openapi3.Server{
			URL: cfg.URL,
		})

		templates, err = openapi.NewTemplates(openapiDoc, cfg.URL)
		if err != nil {
			return errors.Wrap(err, "couldn't create templates from OpenAPI file")
		}
	}

	logger.Info("Test cases loading started")

	testCases, err := db.LoadTestCases(cfg)
	if err != nil {
		return errors.Wrap(err, "loading test case")
	}

	logger.Info("Test cases loading finished")

	db, err := db.NewDB(testCases)
	if err != nil {
		return errors.Wrap(err, "couldn't create test cases DB")
	}

	logger.WithField("fp", db.Hash).Info("Test cases fingerprint")

	dnsCache, err := scanner.NewDNSCache(logger)
	if err != nil {
		return errors.Wrap(err, "couldn't create DNS cache")
	}

	s, err := scanner.New(logger, cfg, db, dnsCache, templates, router, cfg.AddDebugHeader)
	if err != nil {
		return errors.Wrap(err, "couldn't create scanner")
	}

	err = s.Run(ctx)
	if err != nil {
		return errors.Wrap(err, "error occurred while scanning")
	}

	// _, err = os.Stat(cfg.ReportPath)
	// if os.IsNotExist(err) {
	// 	if makeErr := os.Mkdir(cfg.ReportPath, 0700); makeErr != nil {
	// 		return errors.Wrap(makeErr, "creating dir")
	// 	}
	// }

	// reportTime := time.Now()
	// // reportName := reportTime.Format(cfg.ReportName)

	// // reportFile := filepath.Join(cfg.ReportPath, reportName)

	// stat := db.GetStatistics(cfg.IgnoreUnresolved, cfg.NonBlockedAsPassed)

	// err = report.RenderConsoleReport(stat, reportTime, cfg.WAFName, cfg.URL, args, cfg.IgnoreUnresolved, logFormat)
	// if err != nil {
	// 	return err
	// }

	// if cfg.ReportFormat == report.NoneFormat {
	// 	return nil
	// }

	// includePayloads := cfg.IncludePayloads
	// if cfg.ReportFormat == report.HtmlFormat || cfg.ReportFormat == report.PdfFormat {
	// 	askForPayloads := true

	// 	// If the cfg.IncludePayloads is already explicitly set by the user OR
	// 	// the user has explicitly chosen not to send email report, or has
	// 	// provided the email to send the report to (which we interpret as
	// 	// non-interactive mode), do not ask to include the payloads in the report.
	// 	if isIncludePayloadsFlagUsed || cfg.NoEmailReport || cfg.Email != "" {
	// 		askForPayloads = false
	// 	}

	// 	if askForPayloads {
	// 		input := ""
	// 		fmt.Print("Do you want to include payload details to the report? ([y/N]): ")
	// 		fmt.Scanln(&input)

	// 		if strings.TrimSpace(input) == "y" {
	// 			// includePayloads = true
	// 		}
	// 	}
	// }

	// reportFile, err = report.ExportFullReport(
	// 	ctx, stat, reportFile,
	// 	reportTime, cfg.WAFName, cfg.URL, cfg.OpenAPIFile, args,
	// 	cfg.IgnoreUnresolved, includePayloads, cfg.ReportFormat,
	// )
	// if err != nil {
	// 	return errors.Wrap(err, "couldn't export full report")
	// }

	// logger.WithField("filename", reportFile).Infof("Export full report")

	// payloadFiles := filepath.Join(cfg.ReportPath, reportName+".csv")
	// err = db.ExportPayloads(payloadFiles)
	// if err != nil {
	// 	errors.Wrap(err, "payloads exporting")
	// }

	return nil
}
