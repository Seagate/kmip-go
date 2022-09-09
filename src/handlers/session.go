package handlers

import (
	"context"
	"fmt"

	"github.com/Seagate/kmip-go/src/common"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"k8s.io/klog/v2"
)

// Open: Read PEM files and establish a TLS connection with the KMS server
func Open(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Open:", "line", line)

	// Read command line arguments
	ip := common.GetValue(line, "ip")
	if ip != "" {
		settings.KmsServerIp = ip
		fmt.Printf("KmsServerIp set to: %s\n", ip)
	}
	port := common.GetValue(line, "port")
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
func Close(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Close:", "line", line)

	err := kmipapi.CloseSession(ctx, settings)
	if err == nil {
		fmt.Printf("TLS Connection closed with (%s:%s)\n", settings.KmsServerIp, settings.KmsServerPort)
	} else {
		fmt.Printf("TLS Connection failed to close, error: %v\n", err)
	}
}
