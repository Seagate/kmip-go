package kmipapi

type ConfigurationSettings struct {
	LastWritten          int64  `json:"last_written"`           // Unix timestamp (seconds since Jan 1, 1970) this data was last written
	KmsServerIp          string `json:"kms_server_ip"`          // KMS server IP address
	KmsServerPort        string `json:"kms_server_port"`        // KMS server sort, typically 5696
	CertAuthFile         string `json:"cert_auth_file"`         // Client certificate authority PEM file
	KeyFile              string `json:"key_file"`               // Client private key PEM file
	CertFile             string `json:"cert_file"`              // Client certificate PEM file
	ProtocolVersionMajor int    `json:"protocol_version_major"` // Major version, 1, 2, or 3
	ProtocolVersionMinor int    `json:"protocol_version_minor"` // Minor version for 1.4 or 2.0
	ServiceType          string `json:"service_type"`           // The KMIP version service string, kmip14, kmip20, etc
	ShowElapsed          bool   `json:"show_elapsed"`           // Display the elapsed time for each command executed.
	ServerName           string `json:"server_name"`            // ServerName of the KMS server. Normally from CN.
}
