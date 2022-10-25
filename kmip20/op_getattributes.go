package kmip20

import (
	"context"
	"github.com/Seagate/kmip-go"
)

// 4.12 Get Attributes

// Table 196

type GetAttributesRequestPayload struct {
	UniqueIdentifier   *UniqueIdentifierValue // Required: No
	Attributes         interface{}            // Required: No
}

// Table 197

type GetAttributesResponsePayload struct {
	UniqueIdentifier  string      // Required: Yes
	Attributes        interface{} // Required: No
}

type GetAttributesHandler struct {
	GetAttributes func(ctx context.Context, payload *GetAttributesRequestPayload) (*GetAttributesResponsePayload, error)
}

func (h *GetAttributesHandler) HandleItem(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var payload GetAttributesRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.GetAttributes(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
