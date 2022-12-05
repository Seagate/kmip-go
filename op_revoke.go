package kmip

import (
	"context"

	"github.com/Seagate/kmip-go/kmip14"
)

// 4.20 Revoke

// Table 121

type RevocationReasonStruct struct {
	RevocationReasonCode kmip14.RevocationReasonCode // Required: Yes
	RevocationMessage    string                      // Required: No
}

// Table 212

type RevokeRequestPayload struct {
	UniqueIdentifier         string                 // Required: No
	RevocationReason         RevocationReasonStruct // Required: Yes
	CompromiseOccurrenceDate []byte                 // Required: No
}

// Table 213

type RevokeResponsePayload struct {
	UniqueIdentifier string // Required: Yes
}

type RevokeHandler struct {
	Revoke func(ctx context.Context, payload *RevokeRequestPayload) (*RevokeResponsePayload, error)
}

func (h *RevokeHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload RevokeRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Revoke(ctx, &payload)
	if err != nil {
		return nil, err
	}

	req.IDPlaceholder = respPayload.UniqueIdentifier

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
