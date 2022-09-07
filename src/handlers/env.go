package handlers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Seagate/kmip-go/src/common"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"github.com/fatih/color"
	"k8s.io/klog/v2"
)

// Env: usage 'env' to display all configuration settings
func Env(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Env:", "line", line)

	key := color.New(color.FgWhite).SprintFunc()
	value := color.New(color.FgGreen).SprintFunc()

	col1 := 30

	fmt.Println("")
	if settings.Connection == nil {
		fmt.Printf("  %*s  %-v\n", col1, key("Connection"), value(settings.Connection))
	} else {
		fmt.Printf("  %*s  %-v\n", col1, key("Connection"), value(settings.Connection.RemoteAddr()))
	}

	fmt.Println("")
	fmt.Printf("  %*s  %-v\n", col1, key("KmsServerIp"), value(settings.KmsServerIp))
	fmt.Printf("  %*s  %-v\n", col1, key("KmsServerPort"), value(settings.KmsServerPort))
	fmt.Printf("  %*s  %-v\n", col1, key("CertAuthFile"), value(settings.CertAuthFile))
	fmt.Printf("  %*s  %-v\n", col1, key("CertFile"), value(settings.CertFile))
	fmt.Printf("  %*s  %-v\n", col1, key("KeyFile"), value(settings.KeyFile))

	fmt.Println("")
	fmt.Printf("  %*s  %-v\n", col1, key("ProtocolVersionMajor"), value(settings.ProtocolVersionMajor))
	fmt.Printf("  %*s  %-v\n", col1, key("ProtocolVersionMinor"), value(settings.ProtocolVersionMinor))
	fmt.Printf("  %*s  %-v\n", col1, key("ServiceType"), value(settings.ServiceType))
}

// Version: usage 'version [major=<value>] [minor=<value>]' to set KMIP protocol version
func Version(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Version:", "line", line)

	major := common.GetValue(line, "major")
	if major == "" {
		major = "1"
	}

	minor := common.GetValue(line, "minor")
	if minor == "" {
		minor = "4"
	}

	settings.ProtocolVersionMajor, _ = strconv.Atoi(major)
	settings.ProtocolVersionMinor, _ = strconv.Atoi(minor)

	if settings.ProtocolVersionMajor <= 1 {
		settings.ServiceType = kmipapi.KMIP14Service
	} else if settings.ProtocolVersionMajor >= 2 {
		settings.ServiceType = kmipapi.KMIP20Service
	}

	fmt.Printf("kmip protocol version %s.%s\n", major, minor)
}

// Certs: usage 'certs [ca=<value>] [key=<value>] [cert=<value>]' to set certificate PEM files
func Certs(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Certs:", "line", line)

	keys := [3]string{"ca", "key", "cert"}

	for _, key := range keys {
		value := common.GetValue(line, key)
		if value != "" {
			switch key {
			case "ca":
				settings.CertAuthFile = value
				fmt.Printf("CertAuthFile set to: %s\n", value)
			case "key":
				settings.KeyFile = value
				fmt.Printf("KeyFile set to: %s\n", value)
			case "cert":
				settings.CertFile = value
				fmt.Printf("CertFile set to: %s\n", value)
			}
		}
	}
}

// Load: usage 'load file=<value>' to execute all commands in a file
func Load(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Load:", "line", line)

	filename := common.GetValue(line, "file")

	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("File (%s) does not exist\n", filename)
		return
	}

	file, err := os.Open(filename)

	if err != nil {
		fmt.Println(err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\n")
		if len(line) > 0 {
			logger.V(2).Info("process >>>", "line", line)
			Execute(ctx, settings, line)
		}
	}

	file.Close()
}
