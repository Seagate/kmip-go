// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"errors"
)

type KMIPOperations interface {
	CreateKey(context.Context, *ConfigurationSettings, *CreateKeyRequest) (*CreateKeyResponse, error)
	GetKey(context.Context, *ConfigurationSettings, *GetKeyRequest) (*GetKeyResponse, error)
	DestroyKey(context.Context, *ConfigurationSettings, *DestroyKeyRequest) (*DestroyKeyResponse, error)
	ActivateKey(context.Context, *ConfigurationSettings, *ActivateKeyRequest) (*ActivateKeyResponse, error)
	RevokeKey(context.Context, *ConfigurationSettings, *RevokeKeyRequest) (*RevokeKeyResponse, error)
	RegisterKey(context.Context, *ConfigurationSettings, *RegisterKeyRequest) (*RegisterKeyResponse, error)
	Locate(context.Context, *ConfigurationSettings, *LocateRequest) (*LocateResponse, error)
	Query(context.Context, *ConfigurationSettings, *QueryRequest) (*QueryResponse, error)
	SetAttribute(context.Context, *ConfigurationSettings, *SetAttributeRequest) (*SetAttributeResponse, error)
	Discover(context.Context, *ConfigurationSettings, *DiscoverRequest) (*DiscoverResponse, error)
	ReKey(context.Context, *ConfigurationSettings, *ReKeyRequest) (*ReKeyResponse, error)
}

type commonservice struct {
	version string
}

type kmip14service struct {
	service commonservice
	kmip    KMIPOperations
}

type kmip20service struct {
	service commonservice
	kmip    KMIPOperations
}

// Supported interfaces
const (
	KMIP14Service string = "kmip14"
	KMIP20Service string = "kmip20"
)

// NewKMIPInterface : To return specific implementation of KMIP service interface
func NewKMIPInterface(service string, configparams map[string]string) (KMIPOperations, error) {
	comnserv, err := buildCommonService(configparams)
	if err == nil {
		if service == KMIP14Service {
			return &kmip14service{service: comnserv}, nil
		} else if service == KMIP20Service {
			return &kmip20service{service: comnserv}, nil
		}
		return nil, errors.New("Invalid service: " + service)
	}
	return nil, err
}

func buildCommonService(config map[string]string) (commonservice, error) {
	commonserv := commonservice{}
	if config != nil {
		commonserv.version = config["version"]
	}
	return commonserv, nil
}
