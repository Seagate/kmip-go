package kmip20

// import "time"
import "github.com/Seagate/kmip-go"
import "github.com/Seagate/kmip-go/ttlv"
import "github.com/Seagate/kmip-go/kmip14"

type Attributes struct {
	Values ttlv.Values
}

type CreateRequestPayload struct {
	TTLVTag                struct{} `ttlv:"RequestPayload"`
	ObjectType             ObjectType
	Attributes             interface{}
	ProtectionStorageMasks ProtectionStorageMask `ttlv:",omitempty"`
}

type CreateResponsePayload struct {
	ObjectType       ObjectType
	UniqueIdentifier string
}

type CreateKeyPairRequestPayload struct {
	CommonAttributes              interface{}
	PrivateKeyAttributes          interface{}
	PublicKeyAttributes           interface{}
	CommonProtectionStorageMasks  ProtectionStorageMask `ttlv:",omitempty"`
	PrivateProtectionStorageMasks ProtectionStorageMask `ttlv:",omitempty"`
	PublicProtectionStorageMasks  ProtectionStorageMask `ttlv:",omitempty"`
}

type CreateKeyPairResponsePayload struct {
	PrivateKeyUniqueIdentifier string
	PublicKeyUniqueIdentifier  string
}

// GetRequestPayload
type GetRequestPayload struct {
	UniqueIdentifier  UniqueIdentifierValue
}

// GetResponsePayload 
type GetResponsePayload struct {
	ObjectType        ObjectType
	UniqueIdentifier  string
	SymmetricKey      kmip.SymmetricKey
}

// ActivateRequestPayload ////////////////////////////////////////
type ActivateRequestPayload struct {
	UniqueIdentifier  UniqueIdentifierValue
}

// ActivateResponsePayload 
type ActivateResponsePayload struct {
	UniqueIdentifier  string
}

// DestroyRequestPayload ////////////////////////////////////////
type DestroyRequestPayload struct {
	UniqueIdentifier  UniqueIdentifierValue
}

// DestroyResponsePayload 
type DestroyResponsePayload struct {
	UniqueIdentifier  string
}

type RevocationReasonStruct struct {
	RevocationReasonCode kmip14.RevocationReasonCode
}

// RevokeRequestPayload ////////////////////////////////////////
type RevokeRequestPayload struct {
	UniqueIdentifier  UniqueIdentifierValue
	RevocationReason  RevocationReasonStruct
	//CompromiseDate    time.Time
}

// RevokeResponsePayload 
type RevokeResponsePayload struct {
	UniqueIdentifier     string
}

// LocateRequestPayload ////////////////////////////////////////
type LocateRequestPayload struct {
	Attributes    interface{}
}

// LocateResponsePayload
type LocateResponsePayload struct {
    UniqueIdentifier  string
}

// QueryRequestPayload ////////////////////////////////////////
type QueryRequestPayload struct {
	QueryFunction    QueryFunction
}

// LocateResponsePayload
type QueryResponsePayload struct {
    QueryData  string
}

// SetAttributeRequestPayload ////////////////////////////////////////
type SetAttributeRequestPayload struct {
    UniqueIdentifier     UniqueIdentifierValue
	AttributeName        string
    AttributeValue       string
}

// AddAttributeResponsePayload
	type SetAttributeResponsePayload struct {
    UniqueIdentifier     string
	AttributeName        string
    AttributeValue       string
}

