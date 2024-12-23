package kmip

import (
	"context"
)

type ReKeyHandler struct {
	Handler
}

func NewReKeyHandler(rekeyFunc func(ctx context.Context, payload *UniqueIdentifierRequestPayload) (*UniqueIdentifierResponsePayload, error)) *ReKeyHandler {
	return &ReKeyHandler{
		Handler: Handler{
			Process: func(ctx context.Context, payload Payload) (Payload, error) {
				return rekeyFunc(ctx, payload.(*UniqueIdentifierRequestPayload))
			},
		},
	}
}

func (h *ReKeyHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload UniqueIdentifierRequestPayload
	return h.Handler.HandleItem(ctx, req, &payload)
}
