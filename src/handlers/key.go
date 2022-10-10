package handlers

import (
	"context"
	"fmt"

	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"k8s.io/klog/v2"
)

//
// This file contains command line handlers for various operations. They call a common layer of KMIP commands that
// supports various KMIP Protocol versions. These commands use fmt.Printf() calls since we want the 'kms' tool user
// to see the results.
//

// CreateKey: usage 'create id=<value>' to create a new kmip cryptographic key
func CreateKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("CreateKey", "line", line)

	id := kmipapi.GetValue(line, "id")
	if id == "" {
		fmt.Printf("create id=value is required, example: create id=ZAD0YA320000C7300BYS\n")
		return
	}

	uid, err := kmipapi.CreateKey(ctx, settings, id)
	if err != nil {
		fmt.Printf("create key failed for id (%s) with error: %v\n", id, err)
		return
	}

	fmt.Printf("key created for id (%s) returned uid (%s)\n", id, uid)
}

// ActivateKey: usage 'activate uid=<value>' to activate unique identifier
func ActivateKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("ActivateKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("activate uid=value is required, example: activate uid=6201\n")
		return
	}

	uid, err := kmipapi.ActivateKey(ctx, settings, uid)
	if err != nil {
		fmt.Printf("activate key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("key activated for uid (%s)\n", uid)
}

// GetKey: usage 'get uid=<value>' to retrieve kmip cryptographic key material
func GetKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("GetKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")

	if uid == "" {
		fmt.Printf("get uid=value is required, example: get uid=6201\n")
		return
	}

	key, err := kmipapi.GetKey(ctx, settings, uid)
	if err != nil {
		fmt.Printf("get key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("get key for uid (%s) key is (%v)\n", uid, key)
}

// LocateKey: usage 'locate id=<value>' to return the uid of the id, where id is required
func LocateKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("LocateKey", "line", line)

	id := kmipapi.GetValue(line, "id")
	attribname := kmipapi.GetValue(line, "attribname")
	if attribname != "" {
		fmt.Printf("attribname1 set to: %s\n", attribname)
	}
	attribvalue := kmipapi.GetValue(line, "attribvalue")
	if attribvalue != "" {
		fmt.Printf("attribvalue set to: %s\n", attribvalue)
	}

	if id == "" {
		fmt.Printf("locate id=value is required, example: locate id=ZAD0YA320000C7300BYS\n")
		return
	}

	uid, err := kmipapi.LocateUid(ctx, settings, id, attribname, attribvalue)
	if err != nil {
		fmt.Printf("locate failed for id (%s) with error: %v\n", id, err)
		return
	}

	fmt.Printf("locate key for id (%s) returned uid (%s)\n", id, uid)
}

// RevokeKey: usage 'revoke uid=<value>' to revoke a key based on uid
func RevokeKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("RevokeKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("revoke uid=value is required, example: revoke id=6307\n")
		return
	}

	uid, err := kmipapi.RevokeKey(ctx, settings, uid, uint32(kmip14.RevocationReasonCodeCessationOfOperation))

	if err != nil {
		fmt.Printf("revoke key failed for uid (%s) with error: %v\n", uid, err)
	} else {
		fmt.Printf("revoke key succeeded for uid (%s)\n", uid)
	}
}

// DestroyKey: usage 'destroy uid=<value>' to destroy a key based on uid
func DestroyKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("DestroyKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("destroy uid=value is required, example: destroy id=6307\n")
		return
	}

	uid, err := kmipapi.DestroyKey(ctx, settings, uid)
	if err != nil {
		fmt.Printf("destroy key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("destroy key succeeded for uid (%s)\n", uid)
}

// Register:
func RegisterKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Register:", "line", line)

	// Read command line arguments
	keymaterial := kmipapi.GetValue(line, "keymaterial")
	if keymaterial == "" {
		fmt.Printf("register key failed for keymaterial = nil")
	}
	fmt.Printf("register keym (%s)\n", keymaterial)
	keyformat := kmipapi.GetValue(line, "keyformat") // example: opaque
	if keyformat == "" {
		fmt.Printf("keyformat set to: %s\n", keyformat)
	}
	datatype := kmipapi.GetValue(line, "datatype") // example: Password
	if datatype == "" {
		fmt.Printf("datatype set to: %s\n", datatype)
	}
	attribname1 := kmipapi.GetValue(line, "attribname1")
	if attribname1 != "" {
		fmt.Printf("attribname1 set to: %s\n", attribname1)
	}
	attribvalue1 := kmipapi.GetValue(line, "attribvalue1")
	if attribvalue1 != "" {
		fmt.Printf("attribvalue1 set to: %s\n", attribvalue1)
	}
	attribname2 := kmipapi.GetValue(line, "attribname2")
	if attribname1 != "" {
		fmt.Printf("attribname2 set to: %s\n", attribname2)
	}
	attribvalue2 := kmipapi.GetValue(line, "attribvalue2")
	if attribvalue2 != "" {
		fmt.Printf("attribvalue2 set to: %s\n", attribvalue2)
	}
	attribname3 := kmipapi.GetValue(line, "attribname3")
	if attribname3 != "" {
		fmt.Printf("attribname3 set to: %s\n", attribname3)
	}
	attribvalue3 := kmipapi.GetValue(line, "attribvalue3")
	if attribvalue3 != "" {
		fmt.Printf("attribvalue3 set to: %s\n", attribvalue3)
	}
	attribname4 := kmipapi.GetValue(line, "attribname4")
	if attribname4 != "" {
		fmt.Printf("attribname4 set to: %s\n", attribname4)
	}
	attribvalue4 := kmipapi.GetValue(line, "attribvalue4")
	if attribvalue4 != "" {
		fmt.Printf("attribvalue4 set to: %s\n", attribvalue4)
	}
	objtype := kmipapi.GetValue(line, "objtype") // example: secretdata
	if objtype != "" {
		fmt.Printf("objtype set to: %s\n", objtype)
	}
	name := kmipapi.GetValue(line, "name")
	if name != "" {
		fmt.Printf("name set to: %s\n", name)
	}

	// Execute the Register command
	uid, err := kmipapi.RegisterKey(ctx, settings, keymaterial, keyformat, datatype, attribname1, attribvalue1, attribname2, attribvalue2, attribname3, attribvalue3, attribname4, attribvalue4, objtype, name)
	if err != nil {
		fmt.Printf("register key failed with error: %v\n", err)
		return
	}
	fmt.Printf("register key succeeded for uid (%s)\n", uid)
}

// GetAttribute: usage 'destroy uid=<value>' to destroy a key based on uid
func GetAttribute(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("GetAttribute", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("get attribute uid=value is required, example: get attribute id=6307\n")
		return
	}
	attribname1 := kmipapi.GetValue(line, "attribname1")
	if attribname1 != "" {
		fmt.Printf("attribname1 set to: %s\n", attribname1)
	}

	uid, err := kmipapi.GetAttribute(ctx, settings, uid, attribname1)
	if err != nil {
		fmt.Printf("get attribute failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("get attribute succeeded for uid (%s)\n", uid)
}
