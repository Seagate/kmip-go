// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/kmip20"
	"github.com/Seagate/kmip-go/pkg/common"
	"github.com/Seagate/kmip-go/ttlv"
)

// Discover: Send a KMIP OperationDiscoverVersion message
func (kmips *kmip20service) Discover(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *DiscoverRequest) (*DiscoverResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== kmips discover ======")

	// Leave the payload empty to get all supported versions from server
	payload := kmip.DiscoverVersionsRequestPayload{
		ProtocolVersion: req.ClientVersions,
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationDiscoverVersions), &payload, false)
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
func (kmips *kmip20service) Query(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *QueryRequest) (*QueryResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== query server ======", "id", req.Id)

	var err error
	var decoder *ttlv.Decoder
	var item *kmip.ResponseBatchItem

	payload := kmip.QueryRequestPayload{
		QueryFunction: req.QueryFunction,
	}
	decoder, item, err = SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationQuery), &payload, false)
	if err != nil {
		return nil, err
	}

	// Extract the QueryResponsePayload type of message
	var respPayload struct {
		Operation             []kmip14.Operation
		ObjectType            []kmip14.ObjectType
		VendorIdentification  string
		CapabilityInformation kmip20.CapabilityInformation
	}
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode QueryResponsePayload, error: %v", err)
	}

	logger.Debug("Query", "Payload", respPayload)

	return &QueryResponse{Operation: respPayload.Operation, ObjectType: respPayload.ObjectType, VendorIdentification: respPayload.VendorIdentification, CapabilityInformation: respPayload.CapabilityInformation}, nil
}

// CreateKey: Send a KMIP OperationCreate message
func (kmips *kmip20service) CreateKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)

	type createReqAttrs struct {
		CryptographicAlgorithm kmip14.CryptographicAlgorithm
		CryptographicLength    int
		CryptographicUsageMask kmip14.CryptographicUsageMask
		Name                   kmip.Name
	}

	logger.Debug("====== create key ======", "id", req.Id)

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

	decoder, item, err = SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationCreate), &payload, false)
	if err != nil {
		return nil, err
	}

	// Extract the CreateResponsePayload type of message
	var respPayload kmip20.CreateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("create key decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("create key success", "uid", uid)

	return &CreateKeyResponse{UniqueIdentifier: uid}, nil
}

// CreateKey: Send a KMIP OperationCreate message
func (kmips *kmip20service) GenerateCreateKeyPayload(ctx context.Context, settings *ConfigurationSettings, req *CreateKeyRequest) interface{} {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)

	type createReqAttrs struct {
		CryptographicAlgorithm kmip14.CryptographicAlgorithm
		CryptographicLength    int
		CryptographicUsageMask kmip14.CryptographicUsageMask
		Name                   kmip.Name
	}

	logger.Debug("====== batch create key ======", "id", req.Id)

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

	return payload
}

// Locate:
func (kmips *kmip20service) GenerateLocatePayload(ctx context.Context, settings *ConfigurationSettings, req *LocateRequest) interface{} {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== batch locate ======", "name", req.Name)

	type createReqAttrs struct {
		Name kmip.Name
	}

	payload := kmip20.LocateRequestPayload{
		Attributes: createReqAttrs{
			Name: kmip.Name{
				NameValue: req.Name,
				NameType:  kmip14.NameTypeUninterpretedTextString,
			},
		},
	}

	return payload
}

// GetKey: Send a KMIP OperationGet message to retrieve key material based on a uid
func (kmips *kmip20service) GetKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *GetKeyRequest) (*GetKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== get key ======", "uid", req.UniqueIdentifier)

	payload := kmip20.GetRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationGet), &payload, false)
	logger.Debug("get key response item", "item", item)

	// Extract the GetResponsePayload type of message
	var respPayload kmip20.GetResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	logger.Debug("get key decode value")

	if err != nil {
		return nil, fmt.Errorf("get key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("get key success", "uid", uid)

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
				keybytes := hex.EncodeToString(bytes)
				response.KeyValue = &keybytes
				ZeroizeMemory(bytes)
				ZeroizeMemory(respPayload.SymmetricKey.KeyBlock.KeyValue.KeyMaterial.([]byte))
			} else {
				// No bytes to to encode
				nullkey := ""
				response.KeyValue = &nullkey
				ZeroizeMemory(respPayload.SymmetricKey.KeyBlock.KeyValue.KeyMaterial.([]byte))
			}
		}
	}

	return &response, nil
}

// DestroyKey:
func (kmips *kmip20service) DestroyKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *DestroyKeyRequest) (*DestroyKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== destroy key ======", "uid", req.UniqueIdentifier)

	payload := kmip20.DestroyRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationDestroy), &payload, false)
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
	logger.Debug("XXX DestroyKey response payload", "uid", uid)

	return &DestroyKeyResponse{UniqueIdentifier: uid}, nil
}

// ActivateKey:
func (kmips *kmip20service) ActivateKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *ActivateKeyRequest) (*ActivateKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== activate key ======", "uid", req.UniqueIdentifier)

	payload := kmip20.ActivateRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationActivate), &payload, false)
	if err != nil {
		return nil, err
	}

	// Extract the ActivateResponsePayload type of message
	var respPayload kmip20.ActivateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("activate key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("activate key success", "uid", uid)

	return &ActivateKeyResponse{UniqueIdentifier: uid}, nil
}

// RevokeKey:
func (kmips *kmip20service) RevokeKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *RevokeKeyRequest) (*RevokeKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== revoke key ======", "uid", req.UniqueIdentifier)

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

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationRevoke), &payload, false)
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
	logger.Debug("XXX RevokeKey response payload", "uid", uid)

	return &RevokeKeyResponse{UniqueIdentifier: uid}, nil
}

// Register:
func (kmips *kmip20service) Register(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *RegisterRequest) (*RegisterResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)

	type Attribute struct {
		VendorIdentification string
		AttributeName        string
		AttributeValue       interface{}
	}

	type createReqAttrs struct {
		// ObjectGroup kmip20.ObjectGroup
		Attribute []Attribute
		Name      kmip.Name
	}

	logger.Debug("====== register key ======")

	newkey := []byte(req.KeyMaterial)

	payload := kmip20.RegisterRequestPayload{
		ObjectType: kmip14.ObjectTypeSecretData,
		SecretData: &kmip.SecretData{
			SecretDataType: kmip14.SecretDataTypePassword,
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
		AttributeName:        "CustomAttribute1",
		AttributeValue:       "CustomValue1",
	})

	attributes.Attribute = append(attributes.Attribute, Attribute{
		VendorIdentification: "x",
		AttributeName:        "CustomAttribute2",
		AttributeValue:       "CustomValue2",
	})

	attributes.Attribute = append(attributes.Attribute, Attribute{
		VendorIdentification: "x",
		AttributeName:        "CustomAttribute3",
		AttributeValue:       "CustomValue3",
	})

	attributes.Attribute = append(attributes.Attribute, Attribute{
		VendorIdentification: "x",
		AttributeName:        "CustomAttribute4",
		AttributeValue:       "CustomValue4",
	})

	attributes.Name = kmip.Name{
		NameValue: "SASED-M-2-14-name",
		NameType:  kmip14.NameTypeUninterpretedTextString,
	}

	payload.Attributes = attributes

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationRegister), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the RegisterResponsePayload type of message
	var respPayload kmip20.RegisterResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		logger.Error("register key decode value failed", "error", err)
		return nil, fmt.Errorf("register key decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("register key success", "uid", uid)
	return &RegisterResponse{UniqueIdentifier: uid}, nil
}

func (kmips *kmip20service) GetAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *GetAttributeRequest) (*GetAttributeResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)

	logger.Debug("====== get attribute ======")

	type createReqAttrs struct {
		VendorIdentification string
		AttributeName        string
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

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationGetAttributes), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the GetAttributeResponsePayload type of message
	var respPayload kmip20.GetAttributesResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		logger.Error("get attribute decode value failed", "error", err)
		return nil, fmt.Errorf("get attribute decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("get attribute success", "uid", uid)
	return &GetAttributeResponse{UniqueIdentifier: uid}, nil
}

// Locate:
func (kmips *kmip20service) Locate(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *LocateRequest) (*LocateResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== locate ======", "name", req.Name)

	type createReqAttrs struct {
		Name kmip.Name
	}

	payload := kmip20.LocateRequestPayload{
		Attributes: createReqAttrs{
			Name: kmip.Name{
				NameValue: req.Name,
				NameType:  kmip14.NameTypeUninterpretedTextString,
			},
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationLocate), &payload, false)
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
	logger.Debug("XXX Locate response payload", "uid", respPayload.UniqueIdentifier)

	uid := ""
	if len(uids) > 0 {
		uid = uids[0]
	}

	return &LocateResponse{UniqueIdentifier: uid}, nil
}

// SetAttribute:
func (kmips *kmip20service) SetAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *SetAttributeRequest) (*SetAttributeResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== set attribute ======", "uid", req.UniqueIdentifier, "name", req.AttributeName, "value", req.AttributeValue)

	type newAttribute struct {
		AttributeName  string
		AttributeValue string
	}
	payload := kmip20.SetAttributeRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
		NewAttribute: newAttribute{
			AttributeName:  req.AttributeName,
			AttributeValue: req.AttributeValue,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationSetAttribute), &payload, false)
	if err != nil {
		return nil, err
	}

	// Extract the RevokeResponsePayload type of message
	var respPayload kmip20.RevokeResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	logger.Debug("XXX SetAttribute response payload", "uid", respPayload.UniqueIdentifier)

	return &SetAttributeResponse{}, nil
}

// ReKey:
func (kmips *kmip20service) ReKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *ReKeyRequest) (*ReKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== rekey ======", "uid", req.UniqueIdentifier)

	payload := kmip20.ReKeyRequestPayload{
		UniqueIdentifier: &kmip20.UniqueIdentifierValue{
			Text:  req.UniqueIdentifier,
			Enum:  0,
			Index: 0,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip20.OperationReKey), &payload, false)
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
	logger.Debug("xxx ReKey Response Payload", "uid", uid)

	return &ReKeyResponse{UniqueIdentifier: uid}, nil
}
