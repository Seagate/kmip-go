package kmip

import (
	"context"
)

type ReKeyRequestPayload struct {
	UniqueIdentifier string
}

type ReKeyResponsePayload struct {
	UniqueIdentifier string
}

type ReKeyHandler struct {
	ReKey func(ctx context.Context, payload *ReKeyRequestPayload) (*ReKeyResponsePayload, error)
}

func (h *ReKeyHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload ReKeyRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.ReKey(ctx, &payload)
	if err != nil {
		return nil, err
	}

	// req.Key = respPayload.Key

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
