// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"crypto/tls"
	"errors"
)

type KMIPOperations interface {
	CreateKey(context.Context, *tls.Conn, *ConfigurationSettings, *CreateKeyRequest) (*CreateKeyResponse, error)
	GetKey(context.Context, *tls.Conn, *ConfigurationSettings, *GetKeyRequest) (*GetKeyResponse, error)
	DestroyKey(context.Context, *tls.Conn, *ConfigurationSettings, *DestroyKeyRequest) (*DestroyKeyResponse, error)
	ActivateKey(context.Context, *tls.Conn, *ConfigurationSettings, *ActivateKeyRequest) (*ActivateKeyResponse, error)
	RevokeKey(context.Context, *tls.Conn, *ConfigurationSettings, *RevokeKeyRequest) (*RevokeKeyResponse, error)
	Register(context.Context, *tls.Conn, *ConfigurationSettings, *RegisterRequest) (*RegisterResponse, error)
	Locate(context.Context, *tls.Conn, *ConfigurationSettings, *LocateRequest) (*LocateResponse, error)
	Query(context.Context, *tls.Conn, *ConfigurationSettings, *QueryRequest) (*QueryResponse, error)
	SetAttribute(context.Context, *tls.Conn, *ConfigurationSettings, *SetAttributeRequest) (*SetAttributeResponse, error)
	Discover(context.Context, *tls.Conn, *ConfigurationSettings, *DiscoverRequest) (*DiscoverResponse, error)
	ReKey(context.Context, *tls.Conn, *ConfigurationSettings, *ReKeyRequest) (*ReKeyResponse, error)
	GetAttribute(context.Context, *tls.Conn, *ConfigurationSettings, *GetAttributeRequest) (*GetAttributeResponse, error)
	GenerateCreateKeyPayload(context.Context, *ConfigurationSettings, *CreateKeyRequest) interface{}
	GenerateLocatePayload(context.Context, *ConfigurationSettings, *LocateRequest) interface{}
	ModifyAttribute(context.Context, *tls.Conn, *ConfigurationSettings, *ModifyAttributeRequest) (*ModifyAttributeResponse, error)
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
