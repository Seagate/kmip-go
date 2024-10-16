package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/pkg/common"
	"github.com/Seagate/kmip-go/src/kmipapi"
)

// Open: Read PEM files and establish a TLS connection with the KMS server
func Open(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Open:", "line", line)

	// Read command line arguments
	ip := kmipapi.GetValue(line, "ip")
	if ip != "" {
		settings.KmsServerIp = ip
		fmt.Printf("KmsServerIp set to: %s\n", ip)
	}
	port := kmipapi.GetValue(line, "port")
	if port != "" {
		settings.KmsServerPort = port
		fmt.Printf("KmsServerPort set to: %s\n", port)
	}

	// Open a TLS session with the KMS server
	var err error
	*connection, err = kmipapi.OpenSession(ctx, settings)
	if err == nil {
		fmt.Printf("TLS Connection opened with (%s:%s) remote (%v)\n", settings.KmsServerIp, settings.KmsServerPort, (*connection).RemoteAddr())
	} else {
		fmt.Printf("TLS Connection failed to open, error: %v\n", err)
	}
}

// Close: Close the TLS connection
func Close(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Close:", "line", line)

	err := kmipapi.CloseSession(ctx, *connection, settings)
	if err == nil {
		fmt.Printf("TLS Connection closed with (%s:%s)\n", settings.KmsServerIp, settings.KmsServerPort)
	} else {
		fmt.Printf("TLS Connection failed to close, error: %v\n", err)
	}
}

// Discover: Discover versions supported by a KMS Server
func Discover(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Discover:", "line", line)

	// Read command line arguments
	major := kmipapi.GetValue(line, "major")
	minor := kmipapi.GetValue(line, "minor")

	versions := []kmip.ProtocolVersion{}

	if major != "" && minor != "" {
		majorInt, _ := strconv.Atoi(major)
		minorInt, _ := strconv.Atoi(minor)
		versions = append(versions, kmip.ProtocolVersion{ProtocolVersionMajor: majorInt, ProtocolVersionMinor: minorInt})
	}

	results, err := kmipapi.DiscoverServer(ctx, *connection, settings, versions)
	if err == nil {
		fmt.Printf("Discover results: %v\n", results)
	} else {
		fmt.Printf("Discover failed, error: %v\n", err)
	}
}

// Query: Query the KMS Server with a specified operation
func Query(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Query:", "line", line)

	// Read command line arguments
	operation := kmipapi.GetValue(line, "op")
	opsplit := strings.Split(operation, ",")
	queryop := []kmip14.QueryFunction{}

	for _, op := range opsplit {
		u64, _ := strconv.ParseUint(op, 10, 32)
		queryop = append(queryop, kmip14.QueryFunction(uint32(u64)))
	}

	results, err := kmipapi.QueryServer(ctx, *connection, settings, queryop)
	if err == nil {
		fmt.Printf("Query results: %s\n", results)
	} else {
		fmt.Printf("Query failed, error: %v\n", err)
	}
}
