package kmip20

import (
	"context"

	"github.com/Seagate/kmip-go"
)

// 4.12 Get Attributes

// Table 246

type ModifyAttributeRequestPayload struct {
	UniqueIdentifier *UniqueIdentifierValue // Required: Yes
	Attribute        interface{}
	NewAttribute     interface{}
}

// Table 247

type ModifyAttributeResponsePayload struct {
	UniqueIdentifier string // Required: Yes
}

type ModifyAttributeHandler struct {
	ModifyAttribute func(ctx context.Context, payload *ModifyAttributeRequestPayload) (*ModifyAttributeResponsePayload, error)
}

func (h *ModifyAttributeHandler) HandleItem(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var payload ModifyAttributeRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.ModifyAttribute(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
