// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/pkg/common"
	"github.com/Seagate/kmip-go/ttlv"
)

// Discover: Send a KMIP OperationDiscoverVersion message
func (kmips *kmip14service) Discover(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *DiscoverRequest) (*DiscoverResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== kmip discover ======")

	// Leave the payload empty to get all supported versions from server
	payload := kmip.DiscoverVersionsRequestPayload{
		ProtocolVersion: req.ClientVersions,
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationDiscoverVersions), &payload, false)
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
func (kmips *kmip14service) Query(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *QueryRequest) (*QueryResponse, error) {
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
		CapabilityInformation kmip.CapabilityInformation
	}

	if item != nil {
		err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	} else {
		err = fmt.Errorf("query response item is nil")
	}

	if err != nil {
		return nil, fmt.Errorf("unable to decode QueryResponsePayload, error: %v", err)
	}

	logger.Debug("Query", "Payload", respPayload)

	return &QueryResponse{Operation: respPayload.Operation, ObjectType: respPayload.ObjectType, VendorIdentification: respPayload.VendorIdentification, CapabilityInformation: respPayload.CapabilityInformation}, nil
}

// CreateKey: Send a KMIP OperationCreate message
func (kmips *kmip14service) CreateKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)

	logger.Debug("====== create key ======", "id", req.Id)

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

	if req.AttribName != "" {
		payload.TemplateAttribute.Attribute = append(payload.TemplateAttribute.Attribute, kmip.Attribute{
			AttributeName:  req.AttribName,
			AttributeValue: req.AttribValue,
		})
	}

	decoder, item, err = SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationCreate), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the CreateResponsePayload type of message
	var respPayload kmip.CreateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		logger.Error("create key decode value failed", "error", err)
		return nil, fmt.Errorf("create key decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("create key success", "uid", uid)

	return &CreateKeyResponse{UniqueIdentifier: uid}, nil
}

// CreateKey: Send a KMIP OperationCreate message
func (kmips *kmip14service) GenerateCreateKeyPayload(ctx context.Context, settings *ConfigurationSettings, req *CreateKeyRequest) interface{} {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== batch create key payload ======", "id", req.Id)

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

	if req.AttribName != "" {
		payload.TemplateAttribute.Attribute = append(payload.TemplateAttribute.Attribute, kmip.Attribute{
			AttributeName:  req.AttribName,
			AttributeValue: req.AttribValue,
		})
	}

	logger.Debug("create", "Payload", payload)
	return payload
}

// ZeroizeMemory: Write random numbers to a memory location
func ZeroizeMemory(data []byte) {
	for i := range data {
		data[i] = byte(rand.Intn(255))
	}
}

// GetKey: Send a KMIP OperationGet message
func (kmips *kmip14service) GetKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *GetKeyRequest) (*GetKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== get key ======", "uid", req.UniqueIdentifier)

	payload := kmip.GetRequestPayload{}

	if req.UniqueIdentifier != "" {
		payload = kmip.GetRequestPayload{UniqueIdentifier: req.UniqueIdentifier}
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationGet), &payload, false)

	if err != nil {
		logger.Error("get key call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the GetResponsePayload type of message
	var respPayload kmip.GetResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	logger.Debug("get key decode value")

	if err != nil {
		logger.Error("get key decode value failed", "error", err)
		return nil, fmt.Errorf("get key decode value failed, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("get key success", "uid", uid)

	response := GetKeyResponse{
		Type:             respPayload.ObjectType,
		UniqueIdentifier: respPayload.UniqueIdentifier,
	}

	if response.Type == kmip14.ObjectTypeSymmetricKey {
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
	}

	if response.Type == kmip14.ObjectTypeSecretData {
		if response.Type == kmip14.ObjectTypeSecretData {
			if respPayload.SecretData != nil {
				if respPayload.SecretData.KeyBlock.KeyValue != nil {
					if bytes, ok := respPayload.SecretData.KeyBlock.KeyValue.KeyMaterial.([]byte); ok {
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
		}
	}

	return &response, nil
}

// DestroyKey:
func (kmips *kmip14service) DestroyKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *DestroyKeyRequest) (*DestroyKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== destroy key ======", "uid", req.UniqueIdentifier)

	payload := kmip.DestroyRequestPayload{}

	if req.UniqueIdentifier != "" {
		payload = kmip.DestroyRequestPayload{UniqueIdentifier: req.UniqueIdentifier}
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationDestroy), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the DestroyResponsePayload type of message
	var respPayload kmip.DestroyResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("XXX DestroyKey response payload", "uid", uid)

	return &DestroyKeyResponse{UniqueIdentifier: uid}, nil
}

// ActivateKey:
func (kmips *kmip14service) ActivateKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *ActivateKeyRequest) (*ActivateKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== activate key ======", "uid", req.UniqueIdentifier)

	// payload := kmip.ActivateRequestPayload{UniqueIdentifier: req.UniqueIdentifier}
	payload := kmip.ActivateRequestPayload{}

	if req.UniqueIdentifier != "" {
		payload = kmip.ActivateRequestPayload{UniqueIdentifier: req.UniqueIdentifier}
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationActivate), &payload, false)
	if err != nil {
		logger.Error("activate key call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the ActivateResponsePayload type of message
	var respPayload kmip.ActivateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("activate key success", "uid", uid)

	return &ActivateKeyResponse{UniqueIdentifier: uid}, nil
}

// RevokeKey:
func (kmips *kmip14service) RevokeKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *RevokeKeyRequest) (*RevokeKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== revoke key ======", "uid", req.UniqueIdentifier)

	payload := kmip.RevokeRequestPayload{
		UniqueIdentifier: req.UniqueIdentifier,
		RevocationReason: kmip.RevocationReasonStruct{
			RevocationReasonCode: kmip14.RevocationReasonCodeCessationOfOperation,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationRevoke), &payload, false)
	if err != nil {
		logger.Error("revoke key call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the RevokeResponsePayload type of message
	var respPayload kmip.RevokeResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("XXX RevokeKey response payload", "uid", uid)

	return &RevokeKeyResponse{UniqueIdentifier: uid}, nil
}

// Register: Register a key
func (kmips *kmip14service) Register(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *RegisterRequest) (*RegisterResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== register key ======")

	var err error
	var decoder *ttlv.Decoder
	var item *kmip.ResponseBatchItem

	// newkey := hex.EncodeToString([]byte(req.KeyMaterial))
	newkey := []byte(req.KeyMaterial)
	payload := kmip.RegisterRequestPayload{}

	payload = kmip.RegisterRequestPayload{
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

	if req.ObjGrp != "" {
		payload.TemplateAttribute.Append(kmip14.TagObjectGroup, req.ObjGrp) //"SASED-M-2-14-group"
	}

	if req.AttribName1 != "" {
		payload.TemplateAttribute.Attribute = append(payload.TemplateAttribute.Attribute, kmip.Attribute{
			AttributeName:  req.AttribName1,  //"x-CustomAttribute1",
			AttributeValue: req.AttribValue1, //"CustomValue1",
		})
	}
	if req.AttribName2 != "" {
		payload.TemplateAttribute.Attribute = append(payload.TemplateAttribute.Attribute, kmip.Attribute{
			AttributeName:  req.AttribName2,  //"x-CustomAttribute2",
			AttributeValue: req.AttribValue2, //"CustomValue2",
		})
	}
	if req.AttribName3 != "" {
		payload.TemplateAttribute.Attribute = append(payload.TemplateAttribute.Attribute, kmip.Attribute{
			AttributeName:  req.AttribName3,  //"x-CustomAttribute3",
			AttributeValue: req.AttribValue3, //"CustomValue3",
		})
	}
	if req.AttribName4 != "" {
		payload.TemplateAttribute.Attribute = append(payload.TemplateAttribute.Attribute, kmip.Attribute{
			AttributeName:  req.AttribName4,  //"x-CustomAttribute4",
			AttributeValue: req.AttribValue4, //"CustomValue4",
		})
	}
	if req.Name != "" {
		payload.TemplateAttribute.Append(kmip14.TagName, kmip.Name{
			NameValue: req.Name, //"SASED-M-2-14-name",
			NameType:  kmip14.NameTypeUninterpretedTextString,
		})
	}

	decoder, item, err = SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationRegister), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the RegisterResponsePayload type of message
	var respPayload kmip.RegisterResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		logger.Error("register key decode value failed", "error", err)
		return nil, fmt.Errorf("register key decode value failed, error:%v", err)
	}

	uid := respPayload.UniqueIdentifier
	logger.Debug("register key success", "uid", uid)

	return &RegisterResponse{UniqueIdentifier: uid}, nil
}

// GetAttribute:
func (kmips *kmip14service) GetAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *GetAttributeRequest) (*GetAttributeResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== get attribute ======", "req", req)

	payload := kmip.GetAttributesRequestPayload{
		UniqueIdentifier: req.UniqueIdentifier,
		AttributeName:    req.AttributeName,
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationGetAttributes), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the GetAttributesResponsePayload type of message
	var respPayload kmip.GetAttributesResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode GetAttributesResponsePayload, error: %v", err)
	}

	logger.Debug("XXX GetAttribute response payload", "respPayload", respPayload)

	uid := respPayload.UniqueIdentifier
	attrib := respPayload.Attribute
	logger.Debug("XXX GetAttribute response payload", "uid", respPayload.UniqueIdentifier)

	return &GetAttributeResponse{UniqueIdentifier: uid, Attribute: attrib}, nil
}

// GenerateLocatePayload:
func (kmips *kmip14service) GenerateLocatePayload(ctx context.Context, settings *ConfigurationSettings, req *LocateRequest) interface{} {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== batch locate ======", "name", req.Name)

	Name := kmip.Name{
		NameValue: req.Name,
		NameType:  kmip14.NameTypeUninterpretedTextString,
	}

	Val := kmip.Attribute{
		AttributeName:  req.AttribName,  //"x-id",
		AttributeValue: req.AttribValue, //"143",
	}

	payload := kmip.LocateRequestPayload{}

	if req.Name != "" {
		payload.Attribute = append(payload.Attribute, kmip.NewAttributeFromTag(kmip14.TagName, 0, Name))
	}

	if req.Name != "" {
		payload.Attribute = append(payload.Attribute, Val)
	}

	if req.AttribName1 == "ObjectGroup" {
		payload.Attribute = append(payload.Attribute, kmip.NewAttributeFromTag(kmip14.TagObjectGroup, 0, req.AttribValue1))
	}

	if req.AttribName2 == "ObjectType" && req.AttribValue2 == "SecretData" {
		payload.Attribute = append(payload.Attribute, kmip.NewAttributeFromTag(kmip14.TagObjectType, 0, kmip14.ObjectTypeSecretData))
	}

	return payload
}

// Locate:
func (kmips *kmip14service) Locate(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *LocateRequest) (*LocateResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== locate ======", "name", req.Name)

	Name := kmip.Name{
		NameValue: req.Name,
		NameType:  kmip14.NameTypeUninterpretedTextString,
	}

	Val := kmip.Attribute{
		AttributeName:  req.AttribName,  //"x-id",
		AttributeValue: req.AttribValue, //"143",
	}

	payload := kmip.LocateRequestPayload{}

	if req.Name != "" {
		payload.Attribute = append(payload.Attribute, kmip.NewAttributeFromTag(kmip14.TagName, 0, Name))
	}

	if req.AttribName != "" {
		payload.Attribute = append(payload.Attribute, Val)
	}

	if req.AttribName1 == "ObjectGroup" {
		payload.Attribute = append(payload.Attribute, kmip.NewAttributeFromTag(kmip14.TagObjectGroup, 0, req.AttribValue1))
	}

	if req.AttribName2 == "ObjectType" && req.AttribValue2 == "SecretData" {
		payload.Attribute = append(payload.Attribute, kmip.NewAttributeFromTag(kmip14.TagObjectType, 0, kmip14.ObjectTypeSecretData))
	}
	logger.Debug("XXX Locate request payload", "respPayload", payload)
	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationLocate), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the LocateResponsePayload type of message
	var respPayload kmip.LocateResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode GetResponsePayload, error: %v", err)
	}

	logger.Debug("XXX Locate response payload", "respPayload", respPayload)

	uid := respPayload.UniqueIdentifier
	logger.Debug("XXX Locate response payload", "uid", respPayload.UniqueIdentifier)

	return &LocateResponse{UniqueIdentifier: uid}, nil
}

// SetAttribute: Not Supported
func (kmips *kmip14service) SetAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *SetAttributeRequest) (*SetAttributeResponse, error) {
	return &SetAttributeResponse{}, fmt.Errorf("SetAttribute command is not supported")
}

func (kmips *kmip14service) ModifyAttribute(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *ModifyAttributeRequest) (*ModifyAttributeResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== modify attribute ======", "req", req)

	payload := kmip.ModifyAttributesRequestPayload{
		UniqueIdentifier: req.UniqueIdentifier,
		Attribute: kmip.Attribute{
			AttributeName:  req.AttributeName1,
			AttributeValue: req.AttributeValue1,
		},
	}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationModifyAttribute), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
		return nil, err
	}

	// Extract the GetAttributesResponsePayload type of message
	var respPayload kmip.ModifyAttributesResponsePayload
	err = decoder.DecodeValue(&respPayload, item.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, fmt.Errorf("unable to decode ModifyAttributesResponsePayload, error: %v", err)
	}

	logger.Debug("XXX ModifyAttribute response payload", "respPayload", respPayload)

	uid := respPayload.UniqueIdentifier
	attrib := respPayload.Attribute
	logger.Debug("XXX ModifyAttribute response payload", "uid", respPayload.UniqueIdentifier)

	return &ModifyAttributeResponse{UniqueIdentifier: uid, Attribute: attrib}, nil
}

// ReKey:
func (kmips *kmip14service) ReKey(ctx context.Context, connection *tls.Conn, settings *ConfigurationSettings, req *ReKeyRequest) (*ReKeyResponse, error) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("====== rekey ======", "uid", req.UniqueIdentifier)

	payload := kmip.ReKeyRequestPayload{UniqueIdentifier: req.UniqueIdentifier}

	decoder, item, err := SendRequestMessage(ctx, connection, settings, uint32(kmip14.OperationReKey), &payload, false)
	if err != nil {
		logger.Error("The call to SendRequestMessage failed", "error", err)
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
