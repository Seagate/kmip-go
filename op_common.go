package kmip

import (
	"context"
)

type Payload interface{}

type UniqueIdentifierRequestPayload struct {
	UniqueIdentifier string
}

type UniqueIdentifierResponsePayload struct {
	UniqueIdentifier string
}

type Handler struct {
	Process func(ctx context.Context, payload Payload) (Payload, error)
}

func (h *Handler) HandleItem(ctx context.Context, req *Request, reqPayload Payload) (*ResponseBatchItem, error) {
	err := req.DecodePayload(reqPayload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Process(ctx, reqPayload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
