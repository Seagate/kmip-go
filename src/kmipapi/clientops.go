// Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates

package kmipapi

import (
	"time"

	"github.com/Seagate/kmip-go"
	"github.com/Seagate/kmip-go/kmip14"
)

// Protocol
const (
	MaxSupportedProtocolVersionMajor int = 2
	MaxSupportedProtocolVersionMinor int = 0
	MinSupportedProtocolVersionMajor int = 1
	MinSupportedProtocolVersionMinor int = 4
)

type CreateKeyRequest struct {
	// Contains all attributes of a caller request to create a KMIP key.
	// Define if this is a certificate or key, the alg, length, and mask.
	Id                     string
	Type                   kmip14.ObjectType
	Algorithm              kmip14.CryptographicAlgorithm
	CryptographicLength    uint32
	CryptographicUsageMask uint32
}

type CreateKeyResponse struct {
	// Contains all attributes of the newly created key that are relevant to the caller.
	Key               string
	TimeStamp         time.Time // (DateTime/8): 2021-10-11 17:53:05 +0000 UTC
	BatchCount        int       // (Integer/4): 1
	Operation         int       // (Enumeration/4): Create
	UniqueBatchItemID []byte    // (ByteString/16): 0x44ce32c10ee5421bb8e0eb6892dfeccb
	ResultStatus      int       // (Enumeration/4): Success
	ObjectType        int       // (Enumeration/4): SymmetricKey
	UniqueIdentifier  string    // (TextString/1): 7
}

type DeleteKeyRequest struct {
	// Contains all attributes of a caller request to delete a KMIP key.
	Type kmip14.ObjectType
}

type DeleteKeyResponse struct {
	// Contains all attributes of the delete key operation that are relevant to the caller.
	TimeStamp    time.Time // (DateTime/8): 2021-10-11 17:53:05 +0000 UTC
	ResultStatus int       // (Enumeration/4): Success
}

type GetKeyRequest struct {
	// Contains all attributes of a caller request to get a KMIP key.
	UniqueIdentifier string
}

type GetKeyResponse struct {
	// Contains all attributes of the get key operation that are relevant to the caller.
	Type             kmip14.ObjectType
	UniqueIdentifier string
	KeyValue         string
}

type DestroyKeyRequest struct {
	// Contains all attributes of a caller request to destroy a KMIP key.
	UniqueIdentifier string
}

type DestroyKeyResponse struct {
	// Contains all attributes of the destroy key operation that are relevant to the caller.
	UniqueIdentifier string
}

type ActivateKeyRequest struct {
	// Contains all attributes of a caller request to activate a KMIP key.
	UniqueIdentifier string
}

type ActivateKeyResponse struct {
	// Contains all attributes of the Activate key operation that are relevant to the caller.
	UniqueIdentifier string
}

type RevokeKeyRequest struct {
	// Contains all attributes of a caller request to revoke a KMIP key.
	UniqueIdentifier string
	RevocationReason uint32
	CompromiseDate   time.Time // optional
}

type RevokeKeyResponse struct {
	// Contains all attributes of the revoke key operation that are relevant to the caller.
	UniqueIdentifier string
}

type RegisterKeyRequest struct {
	// Contains all attributes of a caller request to register a KMIP key.
	Id                     string
	KeyMaterial            string
	KeyFormat              string
	DataType               string
	ObjGrp                 string
	AttribName1            string
	AttribValue1           string
	AttribName2            string
	AttribValue2           string
	AttribName3            string
	AttribValue3           string
	AttribName4            string
	AttribValue4           string
	Type                   string
	Name                   string
	Algorithm              kmip14.CryptographicAlgorithm
	CryptographicLength    uint32
	CryptographicUsageMask uint32
}

type RegisterKeyResponse struct {
	// Contains all attributes of the revoke key operation that are relevant to the caller.
	UniqueIdentifier string
}

type GetAttributeRequest struct {
	// Contains all attributes of a caller request to revoke a KMIP key.
	UniqueIdentifier string
	AttributeName    string
}

type GetAttributeResponse struct {
	// Contains all attributes of the revoke key operation that are relevant to the caller.
	UniqueIdentifier string
	Attribute        string
}

type LocateRequest struct {
	// Contains all attributes of a caller request to revoke a KMIP key.
	Name             string
	AttribName1      string
	AttribValue1     string
	AttribName2      string
	AttribValue2     string
}

type LocateResponse struct {
	// Contains all attributes of the revoke key operation that are relevant to the caller.
	UniqueIdentifier string
}

const (
	QueryOpsOperation  = "1"
	QueryOpsServerInfo = "3"
)

type QueryRequest struct {
	// Contains all attributes of a caller request for a query.
	QueryFunction []kmip14.QueryFunction
	Id            string
}

type QueryResponse struct {
	// Contains all attributes of the query response operation that are relevant to the caller.
	Operation            []kmip14.Operation  `json:"Operation,omitempty"`
	ObjectType           []kmip14.ObjectType `json:"Object Type,omitempty"`
	VendorIdentification string              `json:"Vendor Identification,omitempty"`
}

type SetAttributeRequest struct {
	// Contains all attributes of a caller request to set an attribute to a managed object.
	UniqueIdentifier string
	AttributeName    string
	AttributeValue   string
}

type SetAttributeResponse struct {
	// Contains all attributes of the set attribute operation that are relevant to the caller.
	UniqueIdentifier string
	AttributeName    string
	AttributeValue   string
}

// Discover:
// The response payload contains a list of protocol versions that are supported by the server.
// The protocol versions are ranked in decreasing order of preference.
// If the client provides the server with a list of supported protocol versions in the request payload,
// the server SHALL return only the protocol versions that are supported by both the client and server.
// The server SHOULD list all the protocol versions supported by both client and server.
// If the protocol version specified in the request header is not specified in the request payload and
// the server does not support any protocol version specified in the request payload,
// the server SHALL return an empty list in the response payload.
// If no protocol versions are specified in the request payload,
// the server SHOULD return all the protocol versions that are supported by the server.
type DiscoverRequest struct {
	ClientVersions []kmip.ProtocolVersion
}

type DiscoverResponse struct {
	SupportedVersions []kmip.ProtocolVersion
}

type ReKeyRequest struct {
	// Contains all attributes of a caller request to request new KMIP key.
	UniqueIdentifier string
}

type ReKeyResponse struct {
	// Contains all attributes of the rekey operation that are relevant to the caller.
	UniqueIdentifier string
}
