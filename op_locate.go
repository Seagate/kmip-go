package kmip

import (
	"context"
)

// 4.9 Locate

// Table 190

type LocateRequestPayload struct {
	// MaximumItems      uint32                   // Required: No
	// OffsetItems       uint32                   // Required: No
	// StorageStatusMask kmip14.StorageStatusMask // Required: No
	// ObjectGroupMember kmip14.ObjectGroupMember // Required: No
	Attribute []Attribute // Required: No
}

// Table 191

type LocateResponsePayload struct {
	UniqueIdentifier []string // Required: No
	Items            uint32
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

	var luid LocateResponsePayload
	for _, cv := range respPayload.UniqueIdentifier {
		luid.UniqueIdentifier = append(luid.UniqueIdentifier, cv)
	}
	//req.IDPlaceholder = respPayload.UniqueIdentifier

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
