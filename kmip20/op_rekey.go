package kmip20

import (
	"context"
	"time"

	"github.com/Seagate/kmip-go"
)

// 6.1.42 Re-key

// Table 278

type ReKeyRequestPayload struct {
	UniqueIdentifier       *UniqueIdentifierValue
	Offset                 time.Time             `ttlv:",omitempty"`
	Attributes             interface{}           `ttlv:",omitempty"`
	ProtectionStorageMasks ProtectionStorageMask `ttlv:",omitempty"`
}

// Table 280

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

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
