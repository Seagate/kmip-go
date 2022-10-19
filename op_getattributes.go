package kmip

import (
	"context"
	//"github.com/Seagate/kmip-go/kmip14"
)

// 4.12 Get Attributes

// Table 196

type GetAttributesRequestPayload struct {
	UniqueIdentifier string // Required: No
	AttributeName    string // Required: No
}

// Table 197

type GetAttributesResponsePayload struct {
	UniqueIdentifier string      // Required: Yes
	Attribute        []Attribute // Required: No
}

type GetAttributesHandler struct {
	GetAttributes func(ctx context.Context, payload *GetAttributesRequestPayload) (*GetAttributesResponsePayload, error)
}

func (h *GetAttributesHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload GetAttributesRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.GetAttributes(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
