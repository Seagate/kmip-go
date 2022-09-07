// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/src/common"
	"k8s.io/klog/v2"
)

// CreateKey: Create a unique identifier for a id and return that uid
func CreateKey(ctx context.Context, settings *common.ConfigurationSettings, id string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ create key", "id", id)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		logger.Error(err, "CreateKey create new KMIP interface")
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
func ActivateKey(ctx context.Context, settings *common.ConfigurationSettings, uid string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ activate key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		logger.Error(err, "ActivateKey create new KMIP interface")
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
func GetKey(ctx context.Context, settings *common.ConfigurationSettings, uid string) (key string, err error) {
	logger := klog.FromContext(ctx)
	logger.V(3).Info("++ get key", "uid", uid)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		logger.Error(err, "failed to initialize KMIP service", "type", settings.ServiceType)
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := GetKeyRequest{
		UniqueIdentifier: uid,
	}

	kmipResp, err := kmipops.GetKey(ctx, settings, &req)
	if err != nil {
		logger.Error(err, "GetKey low-level operation failed for uid", "uid", uid)
		return "", fmt.Errorf("failed to get key using (%s), err: %v", settings.ServiceType, err)
	}

	if kmipResp == nil {
		logger.Error(err, "GetKey low-level operation failed for uid", "uid", uid)
		return "", errors.New("failed to get key, KMIP Response was null")
	}

	logger.V(3).Info("++ get key success", "uid", uid, "key", kmipResp.KeyValue)
	return kmipResp.KeyValue, nil
}

// Locate: retrieve a UID for a ID
func Locate(ctx context.Context, settings *common.ConfigurationSettings, id string) (string, error) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("++ locate uid", "id", id)

	kmipops, err := NewKMIPInterface(settings.ServiceType, nil)
	if err != nil || kmipops == nil {
		logger.Error(err, "Locate create new KMIP interface")
		return "", fmt.Errorf("failed to initialize KMIP service (%s)", settings.ServiceType)
	}

	req := LocateRequest{
		Name: id,
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
