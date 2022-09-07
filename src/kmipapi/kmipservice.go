// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"errors"

	"github.com/Seagate/kmip-go/src/common"
)

type KMIPOperations interface {
	CreateKey(context.Context, *common.ConfigurationSettings, *CreateKeyRequest) (*CreateKeyResponse, error)
	GetKey(context.Context, *common.ConfigurationSettings, *GetKeyRequest) (*GetKeyResponse, error)
	DestroyKey(context.Context, *common.ConfigurationSettings, *DestroyKeyRequest) (*DestroyKeyResponse, error)
	ActivateKey(context.Context, *common.ConfigurationSettings, *ActivateKeyRequest) (*ActivateKeyResponse, error)
	RevokeKey(context.Context, *common.ConfigurationSettings, *RevokeKeyRequest) (*RevokeKeyResponse, error)
	Register(context.Context, *common.ConfigurationSettings, *RegisterRequest) (*RegisterResponse, error)
	Locate(context.Context, *common.ConfigurationSettings, *LocateRequest) (*LocateResponse, error)
	Query(context.Context, *common.ConfigurationSettings, *QueryRequest) (*QueryResponse, error)
	SetAttribute(context.Context, *common.ConfigurationSettings, *SetAttributeRequest) (*SetAttributeResponse, error)
	Discover(context.Context, *common.ConfigurationSettings, *DiscoverRequest) (*DiscoverResponse, error)
	ReKey(context.Context, *common.ConfigurationSettings, *ReKeyRequest) (*ReKeyResponse, error)
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
