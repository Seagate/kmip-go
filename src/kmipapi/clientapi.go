// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/pkg/common"
)

// OpenSession: Read PEM files and establish a TLS connection with the KMS server
func OpenSession(ctx context.Context, settings *ConfigurationSettings) (*tls.Conn, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Open TLS session", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)

	// Open a session
	certificate, err := os.ReadFile(settings.CertAuthFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA (%s)", settings.CertAuthFile)
	}

	certificatePool := x509.NewCertPool()
	ok := certificatePool.AppendCertsFromPEM(certificate)
	if !ok {
		return nil, fmt.Errorf("failed to append certificate from PEM")
	}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 key pair")
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

	connection, err := tls.Dial("tcp", settings.KmsServerIp+":"+settings.KmsServerPort, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS Dial failure: %v", err)
	}

	logger.Debug("TLS Connection opened", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)
	return connection, nil
}

// CloseSession: Close the TLS connection with the KMS Server
func CloseSession(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings) error {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)

	if connection != nil {
		err := connection.Close()
		if err != nil {
			return fmt.Errorf("TLS close failure: %v", err)
		}
	}

	logger.Debug("TLS Connection closed", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)
	return nil
}

// Discover: Perform a discover operation to retrieve KMIP protocol versions supported.
func DiscoverServer(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, clientVersions []kmip.ProtocolVersion) ([]kmip.ProtocolVersion, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("   ++ discover server", "clientVersions", clientVersions)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return nil, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := DiscoverRequest{
		ClientVersions: clientVersions,
	}

	kmipResp, err := kmipops.Discover(ctx, connection, settings, &req)
	logger.Debug("discover response", "kmipResp", kmipResp, "error", err)

	if err != nil {
		return nil, fmt.Errorf("failed to discover server using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return nil, errors.New("failed to discover server, KMIP Response was null")
	}

	return kmipResp.SupportedVersions, nil
}

// QueryServer: Perform a query operation.
func QueryServer(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, queryops []kmip14.QueryFunction) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("   ++ querying server", "queryops", queryops)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := QueryRequest{
		QueryFunction: queryops,
	}

	kmipResp, err := kmipops.Query(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to query server using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to query server, KMIP Response was null")
	}

	// Translate response to JSON data
	js, err := json.MarshalIndent(kmipResp, "", "    ")
	if err != nil {
		return "", fmt.Errorf("unable to translate Query data, error: %v", err)
	}

	return string(js), nil
}

// CreateKey: Create a unique identifier for a id and return that uid
func CreateKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, id string, attribname string, attribvalue string) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ create key", "id", id)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := CreateKeyRequest{
		Id:                     id,
		Type:                   kmip14.ObjectTypeSymmetricKey,
		Algorithm:              kmip14.CryptographicAlgorithmAES,
		CryptographicLength:    256,
		CryptographicUsageMask: 12,
		AttribName:             attribname,
		AttribValue:            attribvalue,
	}

	kmipResp, err := kmipops.CreateKey(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to create key using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to create key, KMIP Response was null")
	}

	// This function returns the created unique identifier so that the call can link it to a serial number
	return kmipResp.UniqueIdentifier, nil
}

// ActivateKey: Activate a key created using a unique identifier
func ActivateKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid string) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ activate key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := ActivateKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.ActivateKey(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to activate key using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to activate key, KMIP Response was null")
	}

	return kmipResp.UniqueIdentifier, nil
}

// GetKey: Retrieve a key for a specified UID
func GetKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid string) (key *string, err error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ get key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return nil, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := GetKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.GetKey(ctx, connection, settings, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to get key using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return nil, errors.New("failed to get key, KMIP Response was null")
	}

	logger.Debug("++ get key success", "uid", uid)
	return kmipResp.KeyValue, nil
}

// RegisterKey: Register a key
func RegisterKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, keymaterial string, keyformat string, datatype string, objgrp string, attribname1 string, attribvalue1 string, attribname2 string, attribvalue2 string, attribname3 string, attribvalue3 string, attribname4 string, attribvalue4 string, objtype string, name string) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ register key ", "name", name)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := RegisterRequest{
		KeyMaterial:  keymaterial,
		KeyFormat:    keyformat,
		DataType:     datatype,
		ObjGrp:       objgrp,
		AttribName1:  attribname1,
		AttribValue1: attribvalue1,
		AttribName2:  attribname2,
		AttribValue2: attribvalue2,
		AttribName3:  attribname3,
		AttribValue3: attribvalue3,
		AttribName4:  attribname4,
		AttribValue4: attribvalue4,
		Type:         objtype,
		Name:         name,
	}

	kmipResp, err := kmipops.Register(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to register using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to register, KMIP Response was null")
	}

	return kmipResp.UniqueIdentifier, nil
}

// GetAttribute: Register a key
func GetAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid string, attribname1 string) (*GetAttributeResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ get attribute ", "uid", uid, "attribute", attribname1)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return nil, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := GetAttributeRequest{
		UniqueIdentifier: uid,
		AttributeName:    "Original Creation Date",
	}

	kmipResp, err := kmipops.GetAttribute(ctx, connection, settings, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to get attribute using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return nil, errors.New("failed to get attribute, KMIP Response was null")
	}

	return kmipResp, nil
}

// ModifyAttribute: Modify an attribute
func ModifyAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid string, attribname1 string, attribvalue1 string, attribname2 string, attribvalue2 string) (*ModifyAttributeResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ modify attribute ", "uid", uid, "attribname1", attribname1, "attribvalue1", attribvalue1, "attribname2", attribname2, "attribvalue1", attribvalue2)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return nil, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := ModifyAttributeRequest{
		UniqueIdentifier: uid,
		AttributeName1:   attribname1,
		AttributeValue1:  attribvalue1,
		AttributeName2:   attribname2,  // used by kmip 2.0 as NewAttribute to replace current attribute
		AttributeValue2:  attribvalue2, // used by kmip 2.0 as NewAttribute to replace current attribute
	}

	kmipResp, err := kmipops.ModifyAttribute(ctx, connection, settings, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to modify attribute using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return nil, errors.New("failed to modify attribute, KMIP Response was null")
	}

	return kmipResp, nil
}

// LocateUid: retrieve a UID for a ID
func LocateUid(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, id string, attribname string, attribvalue string, attribname1 string, attribvalue1 string, attribname2 string, attribvalue2 string) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ locate uid", "id", id)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := LocateRequest{
		Name:         id,
		AttribName:   attribname,
		AttribValue:  attribvalue,
		AttribName1:  attribname1,
		AttribValue1: attribvalue1,
		AttribName2:  attribname2,
		AttribValue2: attribvalue2,
	}

	kmipResp, err := kmipops.Locate(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to locate using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to locate, KMIP Response was null")
	}

	return kmipResp.UniqueIdentifier, nil
}

// RevokeKey: revoke a key based on UID
func RevokeKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid string, reason uint32) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ revoke key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := RevokeKeyRequest{
		UniqueIdentifier: uid,
		RevocationReason: reason,
	}

	kmipResp, err := kmipops.RevokeKey(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to revoke key for uid (%s), err: %v", uid, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to revoke key, KMIP response was nil")
	}

	return kmipResp.UniqueIdentifier, nil
}

// DestroyKey: destroy a key based on UID
func DestroyKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid string) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ destroy key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := DestroyKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.DestroyKey(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to destroy key for uid (%s), err: %v", uid, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to destroy key, KMIP response was nil")
	}

	return kmipResp.UniqueIdentifier, nil
}

// SetAttribute: Set an attribute name and value for an uid
func SetAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid, attributeName, attributeValue string) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ set attribute", "uid", uid, "name", attributeName, "value", attributeValue)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return uid, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := SetAttributeRequest{
		UniqueIdentifier: uid,
		AttributeName:    attributeName,
		AttributeValue:   attributeValue,
	}

	kmipResp, err := kmipops.SetAttribute(ctx, connection, settings, &req)
	if err != nil {
		return uid, fmt.Errorf("failed to set attribute for uid (%s), err: %v", uid, err)
	}

	return kmipResp.UniqueIdentifier, nil
}

// ReKey: Assign a new KMIP key for a uid
func ReKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, uid string) (string, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("++ rekey", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := ReKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.ReKey(ctx, connection, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to rekey using uid (%s), err: %v", uid, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to rekey, KMIP Response was null")
	}

	return kmipResp.UniqueIdentifier, nil
}

type (
	CreateNullStruct struct{}
	RevokeNullStruct struct {
		RevocationReason kmip.RevocationReasonStruct // Required: Yes
	}
)

type BatchListItem struct {
	Operation      kmip14.Operation
	RequestPayload interface{}
}

func BatchCmdCreateList() []kmip.RequestBatchItem {
	var BatchList []kmip.RequestBatchItem
	return BatchList
}

func BatchCmdAddItem(ctx context.Context, BatchList []kmip.RequestBatchItem, BatchItems BatchListItem, batchnum []byte, batchcount byte) ([]kmip.RequestBatchItem, []byte, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)

	batchnum = append(batchnum, byte(batchcount+1))
	BatchList = append(BatchList, kmip.RequestBatchItem{
		UniqueBatchItemID: batchnum[batchcount : batchcount+1],
		Operation:         kmip14.Operation(BatchItems.Operation),
		RequestPayload:    BatchItems.RequestPayload,
	},
	)
	logger.Debug("++ batch cmd add item", "BatchList", BatchList)

	return BatchList, batchnum, nil
}
