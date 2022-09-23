package handlers

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"k8s.io/klog/v2"
)

// Open: Read PEM files and establish a TLS connection with the KMS server
func Open(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Open:", "line", line)

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
	err := kmipapi.OpenSession(ctx, settings)
	if err == nil {
		fmt.Printf("TLS Connection opened with (%s:%s)\n", settings.KmsServerIp, settings.KmsServerPort)
	} else {
		fmt.Printf("TLS Connection failed to open, error: %v\n", err)
	}
}

// Close: Close the TLS connection
func Close(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Close:", "line", line)

	err := kmipapi.CloseSession(ctx, settings)
	if err == nil {
		fmt.Printf("TLS Connection closed with (%s:%s)\n", settings.KmsServerIp, settings.KmsServerPort)
	} else {
		fmt.Printf("TLS Connection failed to close, error: %v\n", err)
	}
}

// Discover: Discover versions supported by a KMS Server
func Discover(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Discover:", "line", line)

	// Read command line arguments
	major := kmipapi.GetValue(line, "major")
	minor := kmipapi.GetValue(line, "minor")

	versions := []kmip.ProtocolVersion{}

	if major != "" && minor != "" {
		majorInt, _ := strconv.Atoi(major)
		minorInt, _ := strconv.Atoi(minor)
		versions = append(versions, kmip.ProtocolVersion{ProtocolVersionMajor: majorInt, ProtocolVersionMinor: minorInt})
	}

	results, err := kmipapi.DiscoverServer(ctx, settings, versions)
	if err == nil {
		fmt.Printf("Discover results: %v\n", results)
	} else {
		fmt.Printf("Discover failed, error: %v\n", err)
	}
}

// Query: Query the KMS Server with a specified operation
func Query(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Query:", "line", line)

	// Read command line arguments
	operation := kmipapi.GetValue(line, "op")

	results, err := kmipapi.QueryServer(ctx, settings, operation)
	if err == nil {
		fmt.Printf("Query results: %s\n", results)
	} else {
		fmt.Printf("Query failed, error: %v\n", err)
	}
}

