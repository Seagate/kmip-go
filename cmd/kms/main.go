package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Seagate/kmip-go/src/handlers"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"k8s.io/klog/v2"
)

const version string = "1.1.2"

// init: called once during program execution
func init() {
	handlers.Initialize()
}

// main: the main application
func main() {
	klog.InitFlags(nil)
	klog.EnableContextualLogging(true)

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

	flag.BoolVar(&usage, "h", false, "Show usage message.")
	flag.Parse()

	if usage {
		flag.Usage()
		os.Exit(0)
	}

	fmt.Printf("[] kms (version=%s)\n\n", version)

	settings := kmipapi.ConfigurationSettings{
		ProtocolVersionMajor: 1,
		ProtocolVersionMinor: 4,
		ServiceType:          kmipapi.KMIP14Service,
	}

	ctx := context.Background()

	// Restore any previously stored configuration settings
	filename := "kms.json"
	if _, err := os.Stat(filename); err == nil {
		kmipapi.Restore(ctx, &settings, filename)
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
			handlers.Execute(ctx, &settings, line)
			fmt.Println("")
		}
	}
}
