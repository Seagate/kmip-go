// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/kmip20"
	"github.com/Seagate/kmip-go/ttlv"
	"k8s.io/klog/v2"
)

// Discover: Send a KMIP OperationDiscoverVersion message
func (kmips *kmip20service) Discover(ctx context.Context, settings *ConfigurationSettings, req *DiscoverRequest) (*DiscoverResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== kmips discover ======")

	// Leave the payload empty to get all supported versions from server
	payload := kmip.DiscoverVersionsRequestPayload{
		ProtocolVersion: req.ClientVersions,
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationDiscoverVersions), &payload)
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
func (kmips *kmip20service) Query(ctx context.Context, settings *ConfigurationSettings, req *QueryRequest) (*QueryResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== query server ======", "id", req.Id)

	var err error
	var decoder *ttlv.Decoder
	var item *kmip.ResponseBatchItem

		payload := kmip.QueryRequestPayload{
			QueryFunction: req.QueryFunction,
		}
		decoder, item, err = SendRequestMessage(ctx, settings, uint32(kmip14.OperationQuery), &payload)

	if err != nil {
		return nil, err
	}

	// Extract the QueryResponsePayload type of message
	var respPayload struct {
		Operation            []kmip14.Operation
		ObjectType           []kmip14.ObjectType
		VendorIdentification string
		CapabilityInformation CapabilityInformation
	}
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode QueryResponsePayload, error: %v", err)
	}

	logger.V(4).Info("Query", "Payload", respPayload)

	return &QueryResponse{Operation: respPayload.Operation, ObjectType: respPayload.ObjectType, VendorIdentification: respPayload.VendorIdentification, CapabilityInformation: respPayload.CapabilityInformation}, nil
}

// CreateKey: Send a KMIP OperationCreate message
func (kmips *kmip20service) CreateKey(ctx context.Context, settings *ConfigurationSettings, req *CreateKeyRequest, BatchOp bool) (*CreateKeyResponse, *kmip.CreateRequestPayload, error) {
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
		return nil, nil, err
	}

	// Extract the CreateResponsePayload type of message
	var respPayload kmip20.CreateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, nil, fmt.Errorf("create key decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("create key success", "uid", uid)

	return &CreateKeyResponse{UniqueIdentifier: uid}, nil, nil
}

// GetKey: Send a KMIP OperationGet message to retrieve key material based on a uid
func (kmips *kmip20service) GetKey(ctx context.Context, settings *ConfigurationSettings, req *GetKeyRequest) (*GetKeyResponse, error) {
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
		return nil, err
	}

	// Extract the GetResponsePayload type of message
	var respPayload kmip20.GetResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	logger.V(5).Info("get key decode value", "response", respPayload)

	if err != nil {
		return nil, fmt.Errorf("get key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("get key success", "uid", uid)

	// Example:
	// ResponsePayload (Structure/144):
	// ObjectType (Enumeration/4): SymmetricKey
	// UniqueIdentifier (TextString/4): 6307
	// SymmetricKey (Structure/104):
	//   KeyBlock (Structure/96):
	//     KeyFormatType (Enumeration/4): Raw
	//     KeyValue (Structure/40):
	//       KeyMaterial (ByteString/32): 0x8a8767b44a422e018cd37db0462330bdac8f2c78a66d91e433b2f39a904ab524
	//     CryptographicAlgorithm (Enumeration/4): AES
	//     CryptographicLength (Integer/4): 256

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
func (kmips *kmip20service) DestroyKey(ctx context.Context, settings *ConfigurationSettings, req *DestroyKeyRequest) (*DestroyKeyResponse, error) {
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

	return &DestroyKeyResponse{UniqueIdentifier: uid}, nil
}

// ActivateKey:
func (kmips *kmip20service) ActivateKey(ctx context.Context, settings *ConfigurationSettings, req *ActivateKeyRequest, BatchOp bool) (*ActivateKeyResponse, *kmip.ActivateRequestPayload, error) {
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
		return nil, nil, err
	}

	// Extract the ActivateResponsePayload type of message
	var respPayload kmip20.ActivateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, nil, fmt.Errorf("activate key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.V(4).Info("activate key success", "uid", uid)

	return &ActivateKeyResponse{UniqueIdentifier: uid}, nil, nil
}

// RevokeKey:
func (kmips *kmip20service) RevokeKey(ctx context.Context, settings *ConfigurationSettings, req *RevokeKeyRequest) (*RevokeKeyResponse, error) {
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

	return &RevokeKeyResponse{UniqueIdentifier: uid}, nil
}

// Register:
func (kmips *kmip20service) Register(ctx context.Context, settings *ConfigurationSettings, req *RegisterRequest) (*RegisterResponse, error) {

	logger := klog.FromContext(ctx)

	type Attribute struct {
		VendorIdentification string
		AttributeName string
		AttributeValue interface{}
	}
	
	type createReqAttrs struct {
		//ObjectGroup kmip20.ObjectGroup
		Attribute  []Attribute
		Name       kmip.Name
	}

    logger.V(4).Info("====== register key ======")

    newkey := []byte(req.KeyMaterial)

    payload := kmip20.RegisterRequestPayload{
	    ObjectType: kmip14.ObjectTypeSecretData,
	    SecretData: &kmip.SecretData{
		    SecretDataType : kmip14.SecretDataTypePassword,
		    KeyBlock: kmip.KeyBlock{
			    KeyFormatType: kmip14.KeyFormatTypeOpaque,
			    KeyValue: &kmip.KeyValue{
				    KeyMaterial: newkey,
			    },
		    },
	    },
    }

	var attributes createReqAttrs


    attributes.Attribute = append(attributes.Attribute, Attribute{
	    VendorIdentification: "x",
	    AttributeName: "CustomAttribute1",
	    AttributeValue: "CustomValue1",
    })

	attributes.Attribute = append(attributes.Attribute, Attribute{
	    VendorIdentification: "x",
	    AttributeName: "CustomAttribute2",
	    AttributeValue: "CustomValue2",
    })

	attributes.Attribute = append(attributes.Attribute, Attribute{
	    VendorIdentification: "x",
	    AttributeName: "CustomAttribute3",
	    AttributeValue: "CustomValue3",
    })

	attributes.Attribute = append(attributes.Attribute, Attribute{
	    VendorIdentification: "x",
	    AttributeName: "CustomAttribute4",
	    AttributeValue: "CustomValue4",
    })

	attributes.Name = kmip.Name{
	    NameValue: "SASED-M-2-14-name",
	    NameType:  kmip14.NameTypeUninterpretedTextString,
    }

	payload.Attributes = attributes
    
	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationRegister), &payload)

    if err != nil {
	    logger.Error(err, "The call to SendRequestMessage failed")
	    return nil, err
    }

    // Extract the RegisterResponsePayload type of message
    var respPayload kmip20.RegisterResponsePayload
    err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

    if err != nil {
	    logger.Error(err, "register key decode value failed")
	    return nil, fmt.Errorf("register key decode value failed, error:%v", err)
    }

    uid := respPayload.UniqueIdentifier
    logger.V(4).Info("register key success", "uid", uid)
    return &RegisterResponse{UniqueIdentifier: uid}, nil

}

func (kmips *kmip20service) GetAttribute(ctx context.Context, settings *ConfigurationSettings, req *GetAttributeRequest) (*GetAttributeResponse, error) {
	//return &GetAttributeResponse{}, fmt.Errorf("ERROR command is not implemented")

	logger := klog.FromContext(ctx)

    logger.V(4).Info("====== get attribute ======")

	type createReqAttrs struct {
		VendorIdentification string
		AttributeName string
	}

    payload := kmip20.GetAttributesRequestPayload{
	    UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
		Attributes: createReqAttrs{
			VendorIdentification: "x",
			AttributeName:        req.AttributeName,
		},
    }

    decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationGetAttributes), &payload)

    if err != nil {
	    logger.Error(err, "The call to SendRequestMessage failed")
	    return nil, err
    }

    // Extract the GetAttributeResponsePayload type of message
    var respPayload kmip20.GetAttributesResponsePayload
    err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

    if err != nil {
	    logger.Error(err, "get attribute decode value failed")
	    return nil, fmt.Errorf("get attribute decode value failed, error:%v", err)
    }

    uid := respPayload.UniqueIdentifier
    logger.V(4).Info("get attribute success", "uid", uid)
    return &GetAttributeResponse{UniqueIdentifier: uid}, nil

}

// Locate:
func (kmips *kmip20service) Locate(ctx context.Context, settings *ConfigurationSettings, req *LocateRequest) (*LocateResponse, error) {
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
		return nil, err
	}

	// Extract the LocateResponsePayload type of message
	var respPayload kmip20.LocateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uids := respPayload.UniqueIdentifier
	logger.V(4).Info("XXX Locate response payload", "uid", respPayload.UniqueIdentifier)

	uid := ""
	if len(uids) > 0 {
		uid = uids[0]
	}

	return &LocateResponse{UniqueIdentifier: uid}, nil
}

// SetAttribute:
func (kmips *kmip20service) SetAttribute(ctx context.Context, settings *ConfigurationSettings, req *SetAttributeRequest) (*SetAttributeResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== set attribute ======", "uid", req.UniqueIdentifier, "value", req.AttributeValue)

	payload := kmip20.SetAttributeRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
		// FIXME		AttributeName:  req.AttributeName,
		// FIXME		AttributeValue: req.AttributeValue,
	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationSetAttribute), &payload)
	if err != nil {
		return nil, err
	}

	// Extract the RevokeResponsePayload type of message
	var respPayload kmip20.RevokeResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))

	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	logger.V(4).Info("XXX SetAttribute response payload", "uid", respPayload.UniqueIdentifier)

	return &SetAttributeResponse{}, nil
}

// ReKey:
func (kmips *kmip20service) ReKey(ctx context.Context, settings *ConfigurationSettings, req *ReKeyRequest) (*ReKeyResponse, error) {
	logger := klog.FromContext(ctx)
	logger.V(4).Info("====== rekey ======", "uid", req.UniqueIdentifier)

	payload := kmip.ReKeyRequestPayload{
		UniqueIdentifier: "FIXME",
	}
	// FIXME		UniqueIdentifier: kmip20.UniqueIdentifierValue{
	// FIXME			Text:  req.UniqueIdentifier,
	// FIXME			Enum:  0,
	// FIXME			Index: 0,
	// FIXME		},
	// FIXME	}

	decoder, item, err := SendRequestMessage(ctx, settings, uint32(kmip20.OperationReKey), &payload)
	if err != nil {
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
