package kmip

import (
	"context"
	//"github.com/Seagate/kmip-go/kmip14"
)

// Modify Attributes

// Table 202

type ModifyAttributesRequestPayload struct {
	UniqueIdentifier string
	Attribute        Attribute
}

// Table 203

type ModifyAttributesResponsePayload struct {
	UniqueIdentifier string    // Required: Yes
	Attribute        Attribute // Required: No
}

type ModifyAttributesHandler struct {
	ModifyAttributes func(ctx context.Context, payload *ModifyAttributesRequestPayload) (*ModifyAttributesResponsePayload, error)
}

func (h *ModifyAttributesHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload ModifyAttributesRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.ModifyAttributes(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
