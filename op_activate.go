package kmip

import (
	"context"
)

type ActivateHandler struct {
	Handler
}

func NewActivateHandler(activateFunc func(ctx context.Context, payload *UniqueIdentifierRequestPayload) (*UniqueIdentifierResponsePayload, error)) *ActivateHandler {
	return &ActivateHandler{
		Handler: Handler{
			Process: func(ctx context.Context, payload Payload) (Payload, error) {
				return activateFunc(ctx, payload.(*UniqueIdentifierRequestPayload))
			},
		},
	}
}

func (h *ActivateHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload UniqueIdentifierRequestPayload
	return h.Handler.HandleItem(ctx, req, &payload)
}
