package kmip

import (
	"context"

	"github.com/Seagate/kmip-go/kmip14"
)

// 6.1.37 Query

// Table 259

type QueryRequestPayload struct {
	QueryFunction []kmip14.QueryFunction
}

type CapabilityInformation struct {
	StreamingCapability     bool                      // Required: No
	AsynchronousCapability  bool                      // Required: No
	AttestationCapability   bool                      // Required: No
	BatchUndoCapability     bool                      // Required: No
	BatchContinueCapability bool                      // Required: No
	UnwrapMode              kmip14.UnwrapMode         // Required: No
	DestroyAction           kmip14.DestroyAction      // Required: No
	ShreddingAlgorithm      kmip14.ShreddingAlgorithm // Required: No
	RNGMode                 kmip14.RNGMode            // Required: No
}
// Table 260

type QueryResponsePayload struct {
	Operation                []kmip14.Operation
	ObjectType               []kmip14.ObjectType
	VendorIdentification     string
	ServerInformation        string
	ApplicationNamespace     string
	ExtensionInformation     string
	AttestationType          kmip14.AttestationType
	RNGParameters            string
	ProfileInformation       []kmip14.ProfileName
	ValidationInformation    []kmip14.ValidationAuthorityType
	CapabilityInformation    CapabilityInformation
	ClientRegistrationMethod kmip14.ClientRegistrationMethod
	DefaultsInformation      string
	ProtectionStorageMasks   string
}

type QueryHandler struct {
	Query func(ctx context.Context, payload *QueryRequestPayload) (*QueryResponsePayload, error)
}

func (h *QueryHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload QueryRequestPayload
	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Query(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
