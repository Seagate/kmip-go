package kmip20

import (
	"context"

	"github.com/Seagate/kmip-go"
)

type ReKeyRequestPayload struct {
	UniqueIdentifier UniqueIdentifierValue
}

type ReKeyResponsePayload struct {
	UniqueIdentifier string
}

type ReKeyHandler struct {
	ReKey func(ctx context.Context, payload *ReKeyRequestPayload) (*ReKeyResponsePayload, error)
}

func (h *ReKeyHandler) HandleItem(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
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

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
