// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"k8s.io/klog/v2"
)

// OpenSession: Read PEM files and establish a TLS connection with the KMS server
func OpenSession(ctx context.Context, settings *ConfigurationSettings) error {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Open TLS session", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)

	// Open a session
	certificate, err := os.ReadFile(settings.CertAuthFile)
	if err != nil {
		return fmt.Errorf("Failed to read CA (%s)", settings.CertAuthFile)
	}

	certificatePool := x509.NewCertPool()
	ok := certificatePool.AppendCertsFromPEM(certificate)
	if !ok {
		return fmt.Errorf("Failed to append certificate from PEM")
	}

	// Load client cert
	cert, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
	if err != nil {
		return fmt.Errorf("Failed to create x509 key pair")
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
		return fmt.Errorf("TLS Dial failure: %v", err)
	}

	logger.V(2).Info("TLS Connection opened", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)
	return nil
}

// CloseSession: Close the TLS connection with the KMS Server
func CloseSession(ctx context.Context, settings *ConfigurationSettings) error {
	logger := klog.FromContext(ctx)

	if settings.Connection != nil {
		err := settings.Connection.Close()
		if err != nil {
			return fmt.Errorf("TLS close failure: %v", err)
		}
		settings.Connection = nil
	}

	logger.V(2).Info("TLS Connection closed", "KmsServerIp", settings.KmsServerIp, "KmsServerPort", settings.KmsServerPort)
	return nil
}

// Discover: Perform a discover operation to retrieve KMIP protocol versions supported.
func DiscoverServer(ctx context.Context, settings *ConfigurationSettings, clientVersions []kmip.ProtocolVersion) ([]kmip.ProtocolVersion, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("   ++ discover server", "clientVersions", clientVersions)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return nil, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := DiscoverRequest{
		ClientVersions: clientVersions,
	}

	kmipResp, err := kmipops.Discover(ctx, settings, &req)
	logger.V(4).Info("discover response", "kmipResp", kmipResp, "error", err)

	if err != nil {
		return nil, fmt.Errorf("failed to discover server using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return nil, errors.New("failed to discover server, KMIP Response was null")
	}

	return kmipResp.SupportedVersions, nil
}

// QueryServer: Perform a query operation.
func QueryServer(ctx context.Context, settings *ConfigurationSettings, queryops []kmip14.QueryFunction) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("   ++ querying server", "queryops", queryops)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := QueryRequest{
		QueryFunction: queryops,
	}

	kmipResp, err := kmipops.Query(ctx, settings, &req)
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
func CreateKey(ctx context.Context, settings *ConfigurationSettings, id string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ create key", "id", id)

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
	}

	kmipResp, err := kmipops.CreateKey(ctx, settings, &req)
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
func ActivateKey(ctx context.Context, settings *ConfigurationSettings, uid string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ activate key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := ActivateKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.ActivateKey(ctx, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to activate key using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to activate key, KMIP Response was null")
	}

	return kmipResp.UniqueIdentifier, nil
}

// GetKey: Retrieve a key for a specified UID
func GetKey(ctx context.Context, settings *ConfigurationSettings, uid string) (key *string, err error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ get key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return nil, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := GetKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.GetKey(ctx, settings, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to get key using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return nil, errors.New("failed to get key, KMIP Response was null")
	}

	logger.V(3).Info("++ get key success", "uid", uid)
	return kmipResp.KeyValue, nil
}

// RegisterKey: Register a key
func RegisterKey(ctx context.Context, settings *ConfigurationSettings, keymaterial string, keyformat string, datatype string, objgrp string, attribname1 string, attribvalue1 string, attribname2 string, attribvalue2 string, attribname3 string, attribvalue3 string, attribname4 string, attribvalue4 string, objtype string, name string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ register key ", "name", name)

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

	kmipResp, err := kmipops.Register(ctx, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to register using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to register, KMIP Response was null")
	}

	return kmipResp.UniqueIdentifier, nil
}

// GetAttribute: Register a key
func GetAttribute(ctx context.Context, settings *ConfigurationSettings, uid string, attribname1 string) (*GetAttributeResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ get attribute ", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return nil, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := GetAttributeRequest{
		UniqueIdentifier: uid,
		AttributeName:    attribname1,
	}

	kmipResp, err := kmipops.GetAttribute(ctx, settings, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to get attribute using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return nil, errors.New("failed to get attribute, KMIP Response was null")
	}

	return kmipResp, nil
}

// LocateUid: retrieve a UID for a ID
func LocateUid(ctx context.Context, settings *ConfigurationSettings, id string, attribname1 string, attribvalue1 string, attribname2 string, attribvalue2 string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ locate uid", "id", id)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := LocateRequest{
		Name:         id,
		AttribName1:  attribname1,
		AttribValue1: attribvalue1,
		AttribName2:  attribname2,
		AttribValue2: attribvalue2,
	}

	kmipResp, err := kmipops.Locate(ctx, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to locate using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to locate, KMIP Response was null")
	}

	return kmipResp.UniqueIdentifier, nil
}

// RevokeKey: revoke a key based on UID
func RevokeKey(ctx context.Context, settings *ConfigurationSettings, uid string, reason uint32) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ revoke key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := RevokeKeyRequest{
		UniqueIdentifier: uid,
		RevocationReason: reason,
	}

	kmipResp, err := kmipops.RevokeKey(ctx, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to revoke key for uid (%s), err: %v", uid, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to revoke key, KMIP response was nil")
	}

	return kmipResp.UniqueIdentifier, nil
}

// DestroyKey: destroy a key based on UID
func DestroyKey(ctx context.Context, settings *ConfigurationSettings, uid string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ destroy key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := DestroyKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.DestroyKey(ctx, settings, &req)
	if err != nil {
		return "", fmt.Errorf("failed to destroy key for uid (%s), err: %v", uid, err)
	}

	if kmipResp == nil {
		return "", errors.New("failed to destroy key, KMIP response was nil")
	}

	return kmipResp.UniqueIdentifier, nil
}

// SetAttribute: Set an attribute name and value for an uid
func SetAttribute(ctx context.Context, settings *ConfigurationSettings, uid, attributeName, attributeValue string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ set attribute", "uid", uid, "name", attributeName, "value", attributeValue)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return uid, fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := SetAttributeRequest{
		UniqueIdentifier: uid,
		AttributeName:    attributeName,
		AttributeValue:   attributeValue,
	}

	kmipResp, err := kmipops.SetAttribute(ctx, settings, &req)
	if err != nil {
		return uid, fmt.Errorf("failed to set attribute for uid (%s), err: %v", uid, err)
	}

	return kmipResp.UniqueIdentifier, nil
}

// ReKey: Assign a new KMIP key for a uid
func ReKey(ctx context.Context, settings *ConfigurationSettings, uid string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ rekey", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := ReKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.ReKey(ctx, settings, &req)
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
	logger := klog.FromContext(ctx)

	batchnum = append(batchnum, byte(batchcount+1))
	BatchList = append(BatchList, kmip.RequestBatchItem{
		UniqueBatchItemID: batchnum[batchcount : batchcount+1],
		Operation:         kmip14.Operation(BatchItems.Operation),
		RequestPayload:    BatchItems.RequestPayload,
	},
	)
	logger.V(2).Info("++ batch cmd add item", "BatchList", BatchList)

	return BatchList, batchnum, nil
}
