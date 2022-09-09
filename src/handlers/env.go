package handlers

import (
	"bufio"
	"context"
	"errors"
	"flag"
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
	fmt.Printf("  %*s  %-v\n", col1, key("SettingsFile"), value(settings.SettingsFile))

	fmt.Println("")
	if settings.Connection == nil {
		fmt.Printf("  %*s  %-v\n", col1, key("Connection"), value(settings.Connection))
	} else {
		fmt.Printf("  %*s  %-v\n", col1, key("Connection"), value(settings.Connection.RemoteAddr()))
	}

	fmt.Println("")
	fmt.Printf("  %*s  %-v\n", col1, key("KmsServerName"), value(settings.KmsServerName))
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
	common.Store(ctx, settings)
}

// Certs: usage 'certs [ca=<value>] [key=<value>] [cert=<value>]' to set certificate PEM files
func Certs(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Certs:", "line", line)

	updated := false
	keys := [3]string{"ca", "key", "cert"}

	for _, key := range keys {
		value := common.GetValue(line, key)
		if value != "" {
			switch key {
			case "ca":
				settings.CertAuthFile = value
				fmt.Printf("CertAuthFile set to: %s\n", value)
				updated = true
			case "key":
				settings.KeyFile = value
				fmt.Printf("KeyFile set to: %s\n", value)
				updated = true
			case "cert":
				settings.CertFile = value
				fmt.Printf("CertFile set to: %s\n", value)
				updated = true
			}
		}
	}

	if updated {
		common.Store(ctx, settings)
	}
}

// Run: usage 'run file=<value>' to execute all commands in a file
func Run(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Run:", "line", line)

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

// Set: usage 'set [level=<value>] [ip=<value>] [port=<value>] [name=<value>]' to change a configuration setting
func Set(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Set:", "line", line)

	// set the log level
	level := common.GetValue(line, "level")
	if level != "" {
		flag.Lookup("v").Value.Set(level)
	}

	// set the KMS Server name
	name := common.GetValue(line, "name")
	if name != "" {
		settings.KmsServerName = name
		fmt.Printf("KmsServerName set to: %s\n", name)
	}

	// set the KMS Server IP Address
	ip := common.GetValue(line, "ip")
	if ip != "" {
		settings.KmsServerIp = ip
		fmt.Printf("KmsServerIp set to: %s\n", ip)
	}

	// set the KMS Server Port
	port := common.GetValue(line, "port")
	if port != "" {
		settings.KmsServerPort = port
		fmt.Printf("KmsServerPort set to: %s\n", port)
	}

	common.Store(ctx, settings)
}

// Load: usage 'load file=<value>' to load configuration settings from a file
func Load(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Load:", "line", line)

	filename := common.GetValue(line, "file")
	if filename != "" {
		err := common.Restore(ctx, settings, filename)
		if err == nil {
			settings.SettingsFile = filename
			fmt.Printf("configuration settings read from (%s)\n", settings.SettingsFile)
		}
	}
}
