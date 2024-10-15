package handlers

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/Seagate/kmip-go/pkg/common"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"github.com/fatih/color"
)

// Env: usage 'env' to display all configuration settings
func Env(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Env:", "line", line)

	key := color.New(color.FgWhite).SprintFunc()
	value := color.New(color.FgGreen).SprintFunc()

	col1 := 30

	fmt.Println("")
	fmt.Printf("  %*s  %-v\n", col1, key("ShowElapsed"), value(settings.ShowElapsed))

	if logger.Enabled(ctx, slog.LevelDebug) {
		fmt.Printf("  %*s  %-v\n", col1, key("LogLevel"), value("DEBUG"))
	} else if logger.Enabled(ctx, slog.LevelInfo) {
		fmt.Printf("  %*s  %-v\n", col1, key("LogLevel"), value("INFO"))
	} else if logger.Enabled(ctx, slog.LevelWarn) {
		fmt.Printf("  %*s  %-v\n", col1, key("LogLevel"), value("WARN"))
	} else if logger.Enabled(ctx, slog.LevelError) {
		fmt.Printf("  %*s  %-v\n", col1, key("LogLevel"), value("ERROR"))
	}

	if *connection == nil {
		fmt.Printf("  %*s  %-v\n", col1, key("Connection"), value(connection))
	} else {
		fmt.Printf("  %*s  %-v\n", col1, key("Connection"), value((*connection).RemoteAddr()))
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
func Version(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Version:", "line", line)

	major := kmipapi.GetValue(line, "major")
	if major == "" {
		major = "1"
	}

	minor := kmipapi.GetValue(line, "minor")
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
	kmipapi.Store(ctx, settings)
}

// Certs: usage 'certs [ca=<value>] [key=<value>] [cert=<value>]' to set certificate PEM files
func Certs(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Certs:", "line", line)

	updated := false
	keys := [3]string{"ca", "key", "cert"}

	for _, key := range keys {
		value := kmipapi.GetValue(line, key)
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
		kmipapi.Store(ctx, settings)
	}
}

// Run: usage 'run file=<value>' to execute all commands in a file
func Run(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Run:", "line", line)

	filename := kmipapi.GetValue(line, "file")

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
			logger.Debug("process >>>", "line", line)
			Execute(ctx, connection, settings, line)
		}
	}

	file.Close()
}

// Set: usage 'set [level=<value>] [ip=<value>] [port=<value>]' to change a configuration setting
func Set(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Set:", "line", line)

	// set the log level
	level := kmipapi.GetValue(line, "level")
	if level != "" {
		if strings.EqualFold(level, "debug") {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}
		if strings.EqualFold(level, "info") {
			slog.SetLogLoggerLevel(slog.LevelInfo)
		}
		if strings.EqualFold(level, "warn") {
			slog.SetLogLoggerLevel(slog.LevelWarn)
		}
		if strings.EqualFold(level, "error") {
			slog.SetLogLoggerLevel(slog.LevelError)
		}
	}

	// set the KMS Server IP Address
	ip := kmipapi.GetValue(line, "ip")
	if ip != "" {
		settings.KmsServerIp = ip
		fmt.Printf("KmsServerIp set to: %s\n", ip)
	}

	// set the KMS Server Port
	port := kmipapi.GetValue(line, "port")
	if port != "" {
		settings.KmsServerPort = port
		fmt.Printf("KmsServerPort set to: %s\n", port)
	}

	// set show elapsed to true|false
	elapsed := kmipapi.GetValue(line, "elapsed")
	if elapsed != "" {
		if strings.EqualFold(elapsed, "true") {
			settings.ShowElapsed = true
			fmt.Printf("ShowElapsed set to: %v\n", settings.ShowElapsed)
		}
		if strings.EqualFold(elapsed, "false") {
			settings.ShowElapsed = false
			fmt.Printf("ShowElapsed set to: %v\n", settings.ShowElapsed)
		}
	}

	kmipapi.Store(ctx, settings)
}

// Load: usage 'load file=<value>' to load configuration settings from a file
func Load(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Load:", "line", line)

	filename := kmipapi.GetValue(line, "file")
	if filename != "" {
		err := kmipapi.Restore(ctx, settings, filename)
		if err == nil {
			fmt.Printf("configuration settings read from (%s)\n", filename)
		}
	}
}

// Banner: usage 'banner title=<value>' to print a separator banner with a title
func Banner(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Banner:", "line", line)

	title := kmipapi.GetValue(line, "title")
	fmt.Printf("\n%s %s %s\n\n", strings.Repeat("=", 40), title, strings.Repeat("=", 40))
}
