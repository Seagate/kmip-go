package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"github.com/Seagate/kmip-go/src/common"
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

	// Open a session
	certificate, err := ioutil.ReadFile(settings.CertAuthFile)
	if err != nil {
		logger.Error(err, "Failed to read CA")
		return
	}

	certificatePool := x509.NewCertPool()
	ok := certificatePool.AppendCertsFromPEM(certificate)
	if !ok {
		logger.Error(err, "Failed to append certificate from PEM")
		return
	}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
	if err != nil {
		logger.Error(err, "Failed to create x509 key pair")
		return
	}

	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		RootCAs:                  certificatePool,
		InsecureSkipVerify:       true,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	settings.Connection, err = tls.Dial("tcp", settings.KmsServerIp+":"+settings.KmsServerPort, tlsConfig)
	if err != nil {
		logger.Error(err, "TLS Dial")
		return
	}

	logger.V(0).Info("TLS Connection opened", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)
}

// Close: Close the TLS connection
func Close(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Close:", "line", line)

	if settings.Connection != nil {
		err := settings.Connection.Close()
		if err != nil {
			logger.Error(err, "TLS Close")
			return
		}
		settings.Connection = nil
	}

	logger.V(0).Info("TLS Connection closed", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)
}
