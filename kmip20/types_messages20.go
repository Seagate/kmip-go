package kmip20

import (
	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
	"time"
)

// 7.1
type RequestMessage struct {
	RequestHeader RequestHeader
	BatchItem     []RequestBatchItem
}

type ResponseMessage struct {
	ResponseHeader ResponseHeader
	BatchItem      []ResponseBatchItem
}

// 7.2
type RequestHeader struct {
	ProtocolVersion              kmip.ProtocolVersion
	MaximumResponseSize          int    `ttlv:",omitempty"`
	ClientCorrelationValue       string `ttlv:",omitempty"`
	ServerCorrelationValue       string `ttlv:",omitempty"`
	AsynchronousIndicator        bool   `ttlv:",omitempty"`
	AttestationCapableIndicator  bool   `ttlv:",omitempty"`
	AttestationType              []kmip14.AttestationType
	Authentication               *kmip.Authentication
	BatchErrorContinuationOption kmip14.BatchErrorContinuationOption `ttlv:",omitempty"`
	BatchOrderOption             bool                                `ttlv:",omitempty"`
	TimeStamp                    *time.Time
	BatchCount                   int
}

type RequestBatchItem struct {
	Operation         Operation
	UniqueBatchItemID []byte `ttlv:",omitempty"`
	RequestPayload    interface{}
	MessageExtension  *kmip.MessageExtension `ttlv:",omitempty"`
}

type ResponseHeader struct {
	ProtocolVersion        kmip.ProtocolVersion
	TimeStamp              time.Time
	Nonce                  *kmip.Nonce
	AttestationType        []kmip14.AttestationType
	ClientCorrelationValue string `ttlv:",omitempty"`
	ServerCorrelationValue string `ttlv:",omitempty"`
	BatchCount             int
}

																														type ResponseBatchItem struct {
	Operation                    Operation `ttlv:",omitempty"`
	UniqueBatchItemID            []byte           `ttlv:",omitempty"`
	ResultStatus                 kmip14.ResultStatus
	ResultReason                 kmip14.ResultReason `ttlv:",omitempty"`
	ResultMessage                string              `ttlv:",omitempty"`
	AsynchronousCorrelationValue []byte              `ttlv:",omitempty"`
	ResponsePayload              interface{}         `ttlv:",omitempty"`
	MessageExtension             *kmip.MessageExtension
}



