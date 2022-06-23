package kmip

import (
	"context"

	"github.com/Seagate/kmip-go/kmip14"
)

// 4.9 Locate

// Table 190

type LocateRequestPayload struct {
	MaximumItems      uint32                   // Required: No
	OffsetItems       uint32                   // Required: No
	StorageStatusMask kmip14.StorageStatusMask // Required: No
	ObjectGroupMember kmip14.ObjectGroupMember // Required: No
	Attributes        interface{}              // Required: No
}

// Table 191

type LocateResponsePayload struct {
	LocatedItems     uint32 // Required: No
	UniqueIdentifier string // Required: No
}

type LocateHandler struct {
	Locate func(ctx context.Context, payload *LocateRequestPayload) (*LocateResponsePayload, error)
}

func (h *LocateHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload LocateRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Locate(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
