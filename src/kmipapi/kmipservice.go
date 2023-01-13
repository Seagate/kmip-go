// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"errors"

	"github.com/Seagate/kmip-go"
	//"github.com/Seagate/kmip-go/kmip20"
)
/*
type KMIPCreatePayload struct{
	Create14 *kmip.CreateRequestPayload
	Create20 *kmip20.CreateRequestPayload
}
*/
type KMIPOperations interface {
	CreateKey(context.Context, *ConfigurationSettings, *CreateKeyRequest, bool) (*CreateKeyResponse, *kmip.CreateRequestPayload, error)
	GetKey(context.Context, *ConfigurationSettings, *GetKeyRequest, bool) (*GetKeyResponse, *kmip.GetRequestPayload, error)
	DestroyKey(context.Context, *ConfigurationSettings, *DestroyKeyRequest, bool) (*DestroyKeyResponse, *kmip.DestroyRequestPayload, error)
	ActivateKey(context.Context, *ConfigurationSettings, *ActivateKeyRequest, bool) (*ActivateKeyResponse, *kmip.ActivateRequestPayload, error)
	RevokeKey(context.Context, *ConfigurationSettings, *RevokeKeyRequest, bool) (*RevokeKeyResponse, *kmip.RevokeRequestPayload, error)
	Register(context.Context, *ConfigurationSettings, *RegisterRequest) (*RegisterResponse, error)
	Locate(context.Context, *ConfigurationSettings, *LocateRequest, bool) (*LocateResponse, *kmip.LocateRequestPayload, error)
	Query(context.Context, *ConfigurationSettings, *QueryRequest) (*QueryResponse, error)
	SetAttribute(context.Context, *ConfigurationSettings, *SetAttributeRequest) (*SetAttributeResponse, error)
	Discover(context.Context, *ConfigurationSettings, *DiscoverRequest) (*DiscoverResponse, error)
	ReKey(context.Context, *ConfigurationSettings, *ReKeyRequest) (*ReKeyResponse, error)
	GetAttribute(context.Context, *ConfigurationSettings, *GetAttributeRequest) (*GetAttributeResponse, error)
	GenerateCreateKeyPayload(context.Context, *ConfigurationSettings, *CreateKeyRequest) (interface{})
	//GenerateActivateKeyPayload(context.Context, *ConfigurationSettings, *ActivateKeyRequest) (interface{}, error)
	//GenerateGetKeyPayload(context.Context, *ConfigurationSettings, *GetKeyRequest) (interface{}, error)
	//GenerateLocatePayload(context.Context, *ConfigurationSettings, *LocateRequest) (interface{}, error)
	//GenerateRevokeKeyPayload(context.Context, *ConfigurationSettings, *RevokeKeyRequest) (interface{}, error)
	//GenerateDestroyKeyPayload(context.Context, *ConfigurationSettings, *DestroyKeyRequest) (interface{}, error)
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
