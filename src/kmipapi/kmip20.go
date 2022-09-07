// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"fmt"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/kmip20"
	"github.com/Seagate/kmip-go/src/common"
	"github.com/Seagate/kmip-go/ttlv"
	"k8s.io/klog/v2"
)

// Discover: Send a KMIP OperationDiscoverVersion message
func (kmips *kmip20service) Discover(ctx context.Context, settings *common.ConfigurationSettings, req *DiscoverRequest) (*DiscoverResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== kmips discover ======")

	var PV []kmip.ProtocolVersion

	// proceed to discover the Server supported protocol version

	// leave the payload empty to get all supported versions from server
	payload := kmip.DiscoverVersionsRequestPayload{
		ProtocolVersion: req.ProtocolVersion,
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationDiscoverVersions), &payload)
	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
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
	PV = respPayload.ProtocolVersion
	PVMajor := respPayload.ProtocolVersion[0].ProtocolVersionMajor
	PVMinor := respPayload.ProtocolVersion[0].ProtocolVersionMinor
	logger.V(4).Info("response payload", "ProtocolVersion", PV, "Major", PVMajor, "Minor", PVMinor)

	// If server supports does not support KMIP 2.0 or higher, set Client version to KMIP 2.0
	if (PVMajor*10 + PVMinor) == (MaxSupportedProtocolVersionMajor*10 + MaxSupportedProtocolVersionMinor) {
		logger.V(0).Info("KMIP Server supports max version", "MaxSupportedProtocolVersionMajor", MaxSupportedProtocolVersionMajor, "MaxSupportedProtocolVersionMinor", MaxSupportedProtocolVersionMinor)
		// common.Auditor().Log(common.Discover, fmt.Sprintf("Set Client ProtocolVersion to (%d.%d)", MaxSupportedProtocolVersionMajor, MaxSupportedProtocolVersionMinor))
		settings.ServiceType = KMIP20Service
	} else if (PVMajor*10 + PVMinor) > (MaxSupportedProtocolVersionMajor*10 + MaxSupportedProtocolVersionMinor) {
		logger.V(0).Info("WARNING: KMIP Server supports a higher version", "MaxSupportedProtocolVersionMajor", MaxSupportedProtocolVersionMajor, "MaxSupportedProtocolVersionMinor", MaxSupportedProtocolVersionMinor)
		// common.Auditor().Log(common.Discover, fmt.Sprintf("Set Client ProtocolVersion to (%d.%d)", MaxSupportedProtocolVersionMajor, MaxSupportedProtocolVersionMinor))
		settings.ServiceType = KMIP20Service
	} else if (PVMajor*10 + PVMinor) >= (MinSupportedProtocolVersionMajor*10 + MinSupportedProtocolVersionMinor) {
		logger.V(0).Info("KMIP Server supports min version", "MinSupportedProtocolVersionMajor", MinSupportedProtocolVersionMajor, "MinSupportedProtocolVersionMinor", MinSupportedProtocolVersionMinor)
		// common.Auditor().Log(common.Discover, fmt.Sprintf("Set Client ProtocolVersion to (%d.%d)", MinSupportedProtocolVersionMajor, MinSupportedProtocolVersionMinor))
		settings.ServiceType = KMIP14Service
	} else {
		logger.V(0).Info("WARNING: KMIP Server does not support minimal version", "MinSupportedProtocolVersionMajor", MinSupportedProtocolVersionMajor, "MinSupportedProtocolVersionMinor", MinSupportedProtocolVersionMinor)
		// common.Auditor().Log(common.Discover, fmt.Sprintf("Set Client ProtocolVersion to (%d.%d)", MinSupportedProtocolVersionMajor, MinSupportedProtocolVersionMinor))
		settings.ServiceType = KMIP14Service
	}

	return &DiscoverResponse{ProtocolVersion: PV}, nil
}

// Query: Retrieve info about KMIP server
func (kmips *kmip20service) Query(ctx context.Context, settings *common.ConfigurationSettings, req *QueryRequest) (*QueryResponse, error) {
	return &QueryResponse{}, fmt.Errorf("Query command is not supported")
	/*
		logger := klog.FromContext(ctx)
		logger.V(4).Info("query server", "id", req.Id)

		var err error
		var decoder *ttlv.Decoder
		var item *kmip.ResponseBatchItem

		if req.Id == "" || req.Id == QueryOpsOperation {
			payload := kmip20.QueryRequestPayload{
				QueryFunction: kmip20.QueryFunctionQueryOperations,
			}
			decoder, item, err = SendRequestMessage(ctx, settings, kmip20.OperationQuery, &payload)

		} else if req.Id == QueryOpsServerInfo {
			payload := kmip20.QueryRequestPayload{
				QueryFunction: kmip20.QueryFunctionQueryServerInformation,
			}
			decoder, item, err = SendRequestMessage(ctx, settings, kmip20.OperationQuery, &payload)
		}

		if err != nil {
			logger.Error(err, "The call to SendRequestMessage failed")
			return nil, err
		}

		// Extract the QueryResponsePayload type of message
		var respPayload struct {
			Operation            []kmip20.Operation
			VendorIdentification string
		}
		err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

		if err != nil {
			return nil, fmt.Errorf("unable to decode QueryResponsePayload, error: %v", err)
		}

		logger.V(4).Info("xxxQueryData", "Payload", respPayload)

		//common.Auditor().Log(common.Query, fmt.Sprintf("Query Server with id=%s VendorIdentification=%s", req.Id, respPayload.VendorIdentification))
		return &QueryResponse{Operation: respPayload.Operation, VendorIdentification: respPayload.VendorIdentification}, nil
	*/
}

// CreateKey: Send a KMIP OperationCreate message
func (kmips *kmip20service) CreateKey(ctx context.Context, settings *common.ConfigurationSettings, req *CreateKeyRequest) (*CreateKeyResponse, error) {
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

	payload := kmip20.CreateRequestPayload{
		ObjectType: kmip20.ObjectTypeSymmetricKey,
		Attributes: createReqAttrs{
			CryptographicAlgorithm: kmip14.CryptographicAlgorithmAES,
			CryptographicLength:    256,
			CryptographicUsageMask: kmip14.CryptographicUsageMaskEncrypt | kmip14.CryptographicUsageMaskDecrypt,
			Name: kmip.Name{
				NameValue: req.Id,
				NameType:  kmip14.NameTypeUninterpretedTextString,
			},
		},
	}

	decoder, item, err = SendRequestMessage(ctx, settings, uint32(kmip20.OperationCreate), &payload)

	if err != nil {
		logger.Error(err, "create key call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the CreateResponsePayload type of message
	var respPayload kmip20.CreateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		logger.Error(err, "create key decode value failed")
		return nil, fmt.Errorf("create key decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("create key success", "uid", uid)
	// common.Auditor().Log(common.Create, fmt.Sprintf("create key successful for id (%s) uid (%s)", req.Id, uid))
	return &CreateKeyResponse{UniqueIdentifier: uid}, nil
}

// GetKey: Send a KMIP OperationGet message
func (kmips *kmip20service) GetKey(ctx context.Context, settings *common.ConfigurationSettings, req *GetKeyRequest) (*GetKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== get key ======", "uid", req.UniqueIdentifier)

	payload := kmip20.GetRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationGet), &payload)
	logger.V(5).Info("get key response item", "item", item)

	if err != nil {
		logger.Error(err, "get key call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the GetResponsePayload type of message
	var respPayload kmip20.GetResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	logger.V(5).Info("get key decode value", "response", respPayload)

	if err != nil {
		logger.Error(err, "get key decode value failed")
		return nil, fmt.Errorf("get key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("get key success", "uid", uid)

	// common.Auditor().Log(common.GetKey, fmt.Sprintf("get key successful for uid (%s)", uid))

	response := GetKeyResponse{
		Type:             respPayload.ObjectType,
		UniqueIdentifier: respPayload.UniqueIdentifier,
		KeyValue:         "FIXME", // hex.EncodeToString(respPayload.Key.KeyBlock.KeyValue.KeyMaterial),
	}

	return &response, nil
}

// DestroyKey:
func (kmips *kmip20service) DestroyKey(ctx context.Context, settings *common.ConfigurationSettings, req *DestroyKeyRequest) (*DestroyKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== destroy key ======", "uid", req.UniqueIdentifier)

	payload := kmip20.DestroyRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationDestroy), &payload)
	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the DestroyResponsePayload type of message
	var respPayload kmip20.DestroyResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("XXX DestroyKey response payload", "uid", uid)

	// common.Auditor().Log(common.Destroy, fmt.Sprintf("destroy key successful for uid (%s)", uid))

	return &DestroyKeyResponse{UniqueIdentifier: uid}, nil
}

// ActivateKey:
func (kmips *kmip20service) ActivateKey(ctx context.Context, settings *common.ConfigurationSettings, req *ActivateKeyRequest) (*ActivateKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== activate key ======", "uid", req.UniqueIdentifier)

	payload := kmip20.ActivateRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationActivate), &payload)
	if err != nil {
		logger.Error(err, "activate key call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the ActivateResponsePayload type of message
	var respPayload kmip20.ActivateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		logger.Error(err, "activate key decode value failed")
		return nil, fmt.Errorf("activate key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("activate key success", "uid", uid)

	// common.Auditor().Log(common.Activate, fmt.Sprintf("activate key successful for uid (%s)", uid))

	return &ActivateKeyResponse{UniqueIdentifier: uid}, nil
}

// RevokeKey:
func (kmips *kmip20service) RevokeKey(ctx context.Context, settings *common.ConfigurationSettings, req *RevokeKeyRequest) (*RevokeKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== revoke key ======", "uid", req.UniqueIdentifier)

	payload := kmip20.RevokeRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
		RevocationReason: kmip20.RevocationReason{
			RevocationReasonCode: kmip14.RevocationReasonCodeCessationOfOperation,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationRevoke), &payload)
	if err != nil {
		logger.Error(err, "revoke key call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the RevokeResponsePayload type of message
	var respPayload kmip20.RevokeResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("XXX RevokeKey response payload", "uid", uid)

	// common.Auditor().Log(common.Revoke, fmt.Sprintf("revoke key successful for uid (%s)", uid))

	return &RevokeKeyResponse{UniqueIdentifier: uid}, nil
}

// Register:
func (kmips *kmip20service) Register(ctx context.Context, settings *common.ConfigurationSettings, req *RegisterRequest) (*RegisterResponse, error) {
	return &RegisterResponse{}, fmt.Errorf("ERROR command is not implemented")
}

// Locate:
func (kmips *kmip20service) Locate(ctx context.Context, settings *common.ConfigurationSettings, req *LocateRequest) (*LocateResponse, error) {
	type createReqAttrs struct {
		Name kmip.Name
	}

	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== locate ======", "name", req.Name)

	payload := kmip20.LocateRequestPayload{
		Attributes: createReqAttrs{
			Name: kmip.Name{
				NameValue: req.Name,
				NameType:  kmip14.NameTypeUninterpretedTextString,
			},
		},
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationLocate), &payload)
	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the LocateResponsePayload type of message
	var respPayload kmip20.LocateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("XXX Locate response payload", "uid", respPayload.UniqueIdentifier)

	// common.Auditor().Log(common.Locate, fmt.Sprintf("uid=%s", uid))
	return &LocateResponse{UniqueIdentifier: uid}, nil
}

// SetAttribute:
func (kmips *kmip20service) SetAttribute(ctx context.Context, settings *common.ConfigurationSettings, req *SetAttributeRequest) (*SetAttributeResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== set attribute ======", "uid", req.UniqueIdentifier, "value", req.AttributeValue)

	payload := kmip20.SetAttributeRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
		//FIXME		AttributeName:  req.AttributeName,
		//FIXME		AttributeValue: req.AttributeValue,
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationSetAttribute), &payload)
	if err != nil {
		logger.Error(err, "The call to SendRequestMessage failed")
		return nil, err
	}

	// Extract the RevokeResponsePayload type of message
	var respPayload kmip20.RevokeResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	logger.V(4).Info("XXX SetAttribute response payload", "uid", respPayload.UniqueIdentifier)

	// common.Auditor().Log(common.SetAttribute, fmt.Sprintf("id=%s DriveSN=%s", req.UniqueIdentifier, req.AttributeValue))

	return &SetAttributeResponse{}, nil
}

// ReKey:
func (kmips *kmip20service) ReKey(ctx context.Context, settings *common.ConfigurationSettings, req *ReKeyRequest) (*ReKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== rekey ======", "uid", req.UniqueIdentifier)

	payload := kmip.ReKeyRequestPayload{
		UniqueIdentifier: "FIXME"}
	//FIXME		UniqueIdentifier: kmip20.UniqueIdentifierValue{
	//FIXME			Text:  req.UniqueIdentifier,
	//FIXME			Enum:  0,
	//FIXME			Index: 0,
	//FIXME		},
	//FIXME	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationReKey), &payload)
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

	// common.Auditor().Log(common.ReKey, fmt.Sprintf("uid=%s", req.UniqueIdentifier))

	return &ReKeyResponse{UniqueIdentifier: uid}, nil
}
