// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/ttlv"
	"k8s.io/klog/v2"
)

// Discover: Send a KMIP OperationDiscoverVersion message
func (kmips *kmip14service) Discover(ctx context.Context, settings *ConfigurationSettings, req *DiscoverRequest) (*DiscoverResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== kmip discover ======")

	// Leave the payload empty to get all supported versions from server
	payload := kmip.DiscoverVersionsRequestPayload{
		ProtocolVersion: req.ClientVersions,
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip14.OperationDiscoverVersions), &payload)
	if err != nil {
		return nil, err
	}

	// Extract the DiscoverResponsePayload type of message
	var respPayload struct {
		ProtocolVersion []kmip.ProtocolVersion
	}
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode DiscoverResponsePayload, error: %v", err)
	}

	return &DiscoverResponse{SupportedVersions: respPayload.ProtocolVersion}, nil
}

// Query: Retrieve info about KMIP server
func (kmips *kmip14service) Query(ctx context.Context, settings *ConfigurationSettings, req *QueryRequest) (*QueryResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== query server ======", "id", req.Id)

	var err error
	var decoder *ttlv.Decoder
	var item *kmip.ResponseBatchItem

	if req.Id == "" || req.Id == QueryOpsOperation {
		payload := kmip.QueryRequestPayload{
			QueryFunction: kmip14.QueryFunctionQueryOperations,
		}
		decoder, item, err = SendRequestMessage(ctx, settings, uint32(kmip14.OperationQuery), &payload)

	} else if req.Id == QueryOpsServerInfo {
		payload := kmip.QueryRequestPayload{
			QueryFunction: kmip14.QueryFunctionQueryServerInformation,
		}
		decoder, item, err = SendRequestMessage(ctx, settings, uint32(kmip14.OperationQuery), &payload)
	}

	if err != nil {
		return nil, err
	}

	// Extract the QueryResponsePayload type of message
	var respPayload struct {
		Operation            []kmip14.Operation
		VendorIdentification string
	}
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode QueryResponsePayload, error: %v", err)
	}

	logger.V(4).Info("Query", "Payload", respPayload)

	return &QueryResponse{Operation: respPayload.Operation, VendorIdentification: respPayload.VendorIdentification}, nil
}

// CreateKey: Send a KMIP OperationCreate message
func (kmips *kmip14service) CreateKey(ctx context.Context, settings *ConfigurationSettings, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	logger := klog.FromContext(ctx)

	type createReqAttrs struct {
		CryptographicAlgorithm kmip14.CryptographicAlgorithm
		CryptographicLength    int
		CryptographicUsageMask kmip14.CryptographicUsageMask
		Name                   kmip.Name
	}

	logger.V(4).Info("====== create key ======", "id", req.Id)

	var err error
	var decoder *ttlv.Decoder
	var item *kmip.ResponseBatchItem

	payload := kmip.CreateRequestPayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
	}

	payload.TemplateAttribute.Append(kmip14.TagCryptographicAlgorithm, kmip14.CryptographicAlgorithmAES)
	payload.TemplateAttribute.Append(kmip14.TagCryptographicLength, 256)
	payload.TemplateAttribute.Append(kmip14.TagCryptographicUsageMask, kmip14.CryptographicUsageMaskEncrypt|kmip14.CryptographicUsageMaskDecrypt)
	payload.TemplateAttribute.Append(kmip14.TagName, kmip.Name{
		NameValue: req.Id,
		NameType:  kmip14.NameTypeUninterpretedTextString,
	})

	decoder, item, err = SendRequestMessage(ctx, settings, uint32(kmip14.OperationCreate), &payload)

	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the CreateResponsePayload type of message
	var respPayload kmip.CreateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		logger.Error(err, "create key decode value failed")
		return nil, fmt.Errorf("create key decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("create key success", "uid", uid)

	return &CreateKeyResponse{UniqueIdentifier: uid}, nil
}

// GetKey: Send a KMIP OperationGet message
func (kmips *kmip14service) GetKey(ctx context.Context, settings *ConfigurationSettings, req *GetKeyRequest) (*GetKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== get key ======", "uid", req.UniqueIdentifier)

	payload := kmip.GetRequestPayload{
		UniqueIdentifier: req.UniqueIdentifier,
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip14.OperationGet), &payload)
	logger.V(5).Info("get key response item", "item", item)

	if err != nil {
		logger.Error(err, "get key call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the GetResponsePayload type of message
	var respPayload kmip.GetResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	logger.V(5).Info("get key decode value", "response", respPayload)

	if err != nil {
		logger.Error(err, "get key decode value failed")
		return nil, fmt.Errorf("get key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("get key success", "uid", uid)

	response := GetKeyResponse{
		Type:             respPayload.ObjectType,
		UniqueIdentifier: respPayload.UniqueIdentifier,
	}

	if respPayload.SymmetricKey != nil {
		if respPayload.SymmetricKey.KeyBlock.KeyValue != nil {
			if bytes, ok := respPayload.SymmetricKey.KeyBlock.KeyValue.KeyMaterial.([]byte); ok {
				// convert byes to an encoded string
				response.KeyValue = hex.EncodeToString(bytes)
			} else {
				// No bytes to to encode
				response.KeyValue = ""
			}
		}
	}

	return &response, nil
}

// DestroyKey:
func (kmips *kmip14service) DestroyKey(ctx context.Context, settings *ConfigurationSettings, req *DestroyKeyRequest) (*DestroyKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== destroy key ======", "uid", req.UniqueIdentifier)

	payload := kmip.DestroyRequestPayload{UniqueIdentifier: req.UniqueIdentifier}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip14.OperationDestroy), &payload)
	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the DestroyResponsePayload type of message
	var respPayload kmip.DestroyResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("XXX DestroyKey response payload", "uid", uid)

	return &DestroyKeyResponse{UniqueIdentifier: uid}, nil
}

// ActivateKey:
func (kmips *kmip14service) ActivateKey(ctx context.Context, settings *ConfigurationSettings, req *ActivateKeyRequest) (*ActivateKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== activate key ======", "uid", req.UniqueIdentifier)

	payload := kmip.ActivateRequestPayload{UniqueIdentifier: req.UniqueIdentifier}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip14.OperationActivate), &payload)
	if err != nil {
		logger.Error(err, "activate key call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the ActivateResponsePayload type of message
	var respPayload kmip.ActivateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("activate key success", "uid", uid)

	return &ActivateKeyResponse{UniqueIdentifier: uid}, nil
}

// RevokeKey:
func (kmips *kmip14service) RevokeKey(ctx context.Context, settings *ConfigurationSettings, req *RevokeKeyRequest) (*RevokeKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== revoke key ======", "uid", req.UniqueIdentifier)

	payload := kmip.RevokeRequestPayload{
		UniqueIdentifier: req.UniqueIdentifier,
		RevocationReason: kmip.RevocationReasonStruct{
			RevocationReasonCode: kmip14.RevocationReasonCodeCessationOfOperation,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip14.OperationRevoke), &payload)
	if err != nil {
		logger.Error(err, "revoke key call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the RevokeResponsePayload type of message
	var respPayload kmip.RevokeResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("XXX RevokeKey response payload", "uid", uid)

	return &RevokeKeyResponse{UniqueIdentifier: uid}, nil
}

// Register: Not Implemented
func (kmips *kmip14service) Register(ctx context.Context, settings *ConfigurationSettings, req *RegisterRequest) (*RegisterResponse, error) {
	return &RegisterResponse{}, fmt.Errorf("command is not implemented")
}

// Locate:
func (kmips *kmip14service) Locate(ctx context.Context, settings *ConfigurationSettings, req *LocateRequest) (*LocateResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== locate ======", "name", req.Name)

	Name := kmip.Name{
		NameValue: req.Name,
		NameType:  kmip14.NameTypeUninterpretedTextString,
	}
	payload := kmip.LocateRequestPayload{}
	payload.Attribute = append(payload.Attribute, kmip.NewAttributeFromTag(kmip14.TagName, 0, Name))

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip14.OperationLocate), &payload)
	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the LocateResponsePayload type of message
	var respPayload kmip.LocateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("XXX Locate response payload", "uid", respPayload.UniqueIdentifier)

	return &LocateResponse{UniqueIdentifier: uid}, nil
}

// SetAttribute: Not Supported
func (kmips *kmip14service) SetAttribute(ctx context.Context, settings *ConfigurationSettings, req *SetAttributeRequest) (*SetAttributeResponse, error) {
	return &SetAttributeResponse{}, fmt.Errorf("SetAttribute command is not supported")
}

// ReKey:
func (kmips *kmip14service) ReKey(ctx context.Context, settings *ConfigurationSettings, req *ReKeyRequest) (*ReKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== rekey ======", "uid", req.UniqueIdentifier)

	payload := kmip.ReKeyRequestPayload{UniqueIdentifier: req.UniqueIdentifier}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip14.OperationReKey), &payload)
	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the RekeyResponsePayload type of message
	var respPayload kmip.ReKeyResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("xxx ReKey Response Payload", "uid", uid)

	return &ReKeyResponse{UniqueIdentifier: uid}, nil
}
