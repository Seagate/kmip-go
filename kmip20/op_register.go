package kmip20

import (
	"context"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"github.com/ansel1/merry"
)

// 4.3

// Table 169

type RegisterRequestPayload struct {
	ObjectType              kmip14.ObjectType
	Attributes              interface{}
	Certificate             *kmip.Certificate
	SymmetricKey            *kmip.SymmetricKey
	PrivateKey              *kmip.PrivateKey
	PublicKey               *kmip.PublicKey
	SplitKey                *kmip.SplitKey
	Template                *kmip.Template
	SecretData              *kmip.SecretData
	OpaqueObject            *kmip.OpaqueObject
	ProtectionStorageMasks  uint32
}

// Table 170

type RegisterResponsePayload struct {
	UniqueIdentifier  string
}

type RegisterHandler struct {
	SkipValidation bool
	RegisterFunc   func(context.Context, *RegisterRequestPayload) (*RegisterResponsePayload, error)
}

func (h *RegisterHandler) HandleItem(ctx context.Context, req *kmip.Request) (item *kmip.ResponseBatchItem, err error) {
	var payload RegisterRequestPayload

	err = req.DecodePayload(&payload)
	if err != nil {
		return nil, merry.Prepend(err, "decoding request")
	}

	if !h.SkipValidation {
		var payloadPresent bool

		switch payload.ObjectType {
		default:
			return nil, kmip.WithResultReason(merry.UserError("Object Type is not recognized"), kmip14.ResultReasonInvalidField)
		case kmip14.ObjectTypeCertificate:
			payloadPresent = payload.Certificate != nil
		case kmip14.ObjectTypeSymmetricKey:
			payloadPresent = payload.SymmetricKey != nil
		case kmip14.ObjectTypePrivateKey:
			payloadPresent = payload.PrivateKey != nil
		case kmip14.ObjectTypePublicKey:
			payloadPresent = payload.PublicKey != nil
		case kmip14.ObjectTypeSplitKey:
			payloadPresent = payload.SplitKey != nil
		case kmip14.ObjectTypeTemplate:
			payloadPresent = payload.Template != nil
		case kmip14.ObjectTypeSecretData:
			payloadPresent = payload.SecretData != nil
		case kmip14.ObjectTypeOpaqueObject:
			payloadPresent = payload.OpaqueObject != nil
		}

		if !payloadPresent {
			return nil, kmip.WithResultReason(merry.UserErrorf("Object Type %s does not match type of cryptographic object provided", payload.ObjectType.String()), kmip14.ResultReasonInvalidField)
		}
	}

	respPayload, err := h.RegisterFunc(ctx, &payload)
	if err != nil {
		return nil, err
	}

	req.IDPlaceholder = respPayload.UniqueIdentifier

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
