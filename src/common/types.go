package common

import "crypto/tls"

type ConfigurationSettings struct {
	KmsServerIp          string    // KMS server IP address
	KmsServerPort        string    // KMS server sort, typically 5696
	CertAuthFile         string    // Client certificate authority PEM file
	KeyFile              string    // Client private key PEM file
	CertFile             string    // Client certificate PEM file
	Connection           *tls.Conn // The TLS connection object returned from Dial
	ProtocolVersionMajor int       // Major version, 1, 2, or 3
	ProtocolVersionMinor int       // Minor version for 1.4 or 2.0
	ServiceType          string    // The KMIP version service string, kmip14, kmip20, etc
}
