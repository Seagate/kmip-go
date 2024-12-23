package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/Seagate/kmip-go/pkg/common"
	"github.com/Seagate/kmip-go/src/handlers"
	"github.com/Seagate/kmip-go/src/kmipapi"
)

const version string = "1.3.0"

// This variable is filled in during the linker step - -ldflags "-X main.buildTime=`date -u '+%Y-%m-%dT%H:%M:%S'`"
var buildTime = ""

// This variable is used to store the TLS connection for an open session with a KMS server
var tlsConnection *tls.Conn = nil

// init: called once during program execution
func init() {
	handlers.Initialize()
}

// main: the main application
func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "[] kms (version=%s) usage:\n", version)
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "This is an interactive Key Management System (KMS) tool for executing KMIP commands.")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "Run ./kms then `kms) help` to get started.")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "")
		flag.PrintDefaults()
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "")
	}

	var usage bool
	var debug bool

	flag.BoolVar(&usage, "h", false, "Show usage message.")
	flag.BoolVar(&debug, "d", false, "Enable debug log level.")
	flag.Parse()

	if usage {
		flag.Usage()
		os.Exit(0)
	}

	// Initialize the slog logger
	logger := slog.Default()

	if debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	fmt.Printf("\n[] kms (version=%s %s)\n\n", version, buildTime)

	settings := kmipapi.ConfigurationSettings{
		ProtocolVersionMajor: 1,
		ProtocolVersionMinor: 4,
		ServiceType:          kmipapi.KMIP14Service,
	}

	ctx := context.WithValue(context.Background(), common.LoggerKey, logger)

	// Restore any previously stored configuration settings
	err := kmipapi.Restore(ctx, &settings, "")
	if err != nil {
		fmt.Printf("ERROR: restoring kms configuration data, error: %v", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("kms) ")
		if scanner.Scan() {
			line := scanner.Text()
			if line == "exit" || line == "quit" {
				fmt.Println("")
				os.Exit(0)
			}
			if line != "" {
				handlers.Execute(ctx, &tlsConnection, &settings, line)
				fmt.Println("")
			}
		}
	}
}
