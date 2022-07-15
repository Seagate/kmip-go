package kmip20

import (
	"context"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
)

// GetRequestPayload ////////////////////////////////////////
//
type GetRequestPayload struct {
	UniqueIdentifier UniqueIdentifierValue
}

// Example:
// ObjectType (Enumeration/4): SymmetricKey
// UniqueIdentifier (TextString/4): 5976
// SymmetricKey (Structure/104):
//   KeyBlock (Structure/96):
//     KeyFormatType (Enumeration/4): Raw
//     KeyValue (Structure/40):
//       KeyMaterial (ByteString/32): 0x1645497fb8ca4f568aba750c7b764ce2700696a5918b2acc9857fae2b1b9f764
//     CryptographicAlgorithm (Enumeration/4): AES
//     CryptographicLength (Integer/4): 256 MessageExtension:<nil>}

// GetResponsePayload
type GetResponsePayload struct {
	ObjectType       kmip14.ObjectType
	UniqueIdentifier string
	SymmetricKey     kmip.SymmetricKey
}

type GetHandler struct {
	Get func(ctx context.Context, payload *GetRequestPayload) (*GetResponsePayload, error)
}

func (h *GetHandler) HandleItem(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var payload GetRequestPayload
	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Get(ctx, &payload)
	if err != nil {
		return nil, err
	}

	//req.Key = respPayload.Key
	req.IDPlaceholder = respPayload.UniqueIdentifier

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
