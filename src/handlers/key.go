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

	// Store the returned uid in ${lastuid} for use in other commands with that variable
	kmipapi.SetValue(kmipapi.LastUID, uid)

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

// ReKey: usage 'activate uid=<value>' to activate unique identifier
func ReKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("ReKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("rekey uid=value is required, example: rekey uid=6201\n")
		return
	}

	uid, err := kmipapi.ReKey(ctx, settings, uid)
	if err != nil {
		fmt.Printf("rekey key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("rekey for uid (%s)\n", uid)
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

	fmt.Printf("get key for uid (%s)\n", *key)
}

// LocateKey: usage 'locate id=<value>' to return the uid of the id, where id is required
func LocateKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("LocateKey", "line", line)

	id := kmipapi.GetValue(line, "id")
	attribname1 := kmipapi.GetValue(line, "attribname1")
	attribvalue1 := kmipapi.GetValue(line, "attribvalue1")
	attribname2 := kmipapi.GetValue(line, "attribname2")
	attribvalue2 := kmipapi.GetValue(line, "attribvalue2")

	if id == "" && attribvalue2 == "" {
		fmt.Printf("locate id, attribname2, and attribvalue2 are required, example: locate id=SASED-M-2-14-name attribname2=ObjectType attribvalue2=SecretData\n")
		return
	}

	uid, item, err := kmipapi.LocateUid(ctx, settings, id, attribname1, attribvalue1, attribname2, attribvalue2)
	if err != nil {
		fmt.Printf("locate failed for id (%s) with error: %v\n", id, err)
		return
	}

	// Store the returned uid in ${lastuid} for use in other commands with that variable
	kmipapi.SetValue(kmipapi.LastUID, uid[0])

	fmt.Printf("locate key for id (%s) returned uid (%s) item (%d)\n", id, uid, item)
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

// ClearKey: usage 'clear id=<value>' to locate, revoke, and destroy a key based on id and uid
func ClearKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("ClearKey", "line", line)

	id := kmipapi.GetValue(line, "id")
	if id == "" {
		fmt.Printf("clear id=value is required, example: clear id=DISK01234\n")
		return
	}

	success := true

	uid, item, err := kmipapi.LocateUid(ctx, settings, id, "", "", "", "")
	//if err != nil || uid == "" {
	if err != nil {
		fmt.Printf("locate failed for id (%s), uid (%d), error: %v\n", id, uid, err)
		success = false
	} else {
		fmt.Printf("locate key for id (%s) returned uid (%s) item (%d)\n", id, uid, item)
		fmt.Printf("\n")

		uid[0], err = kmipapi.RevokeKey(ctx, settings, uid[0], uint32(kmip14.RevocationReasonCodeCessationOfOperation))
		if err != nil {
			fmt.Printf("revoke key failed for uid (%s) with error: %v\n", uid, err)
			success = false
		} else {
			fmt.Printf("revoke key succeeded for uid (%s)\n", uid)
		}
		fmt.Printf("\n")

		uid[0], err = kmipapi.DestroyKey(ctx, settings, uid[0])
		if err != nil {
			fmt.Printf("destroy key failed for uid (%s) with error: %v\n", uid, err)
			success = false
		} else {
			fmt.Printf("destroy key succeeded for uid (%s)\n", uid)
		}
		fmt.Printf("\n")
	}

	if success {
		fmt.Printf("clear key succeeded for id (%s)\n", id)
	} else {
		fmt.Printf("clear key failed for id (%s)\n", id)
	}
}

// Register:
func RegisterKey(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Register:", "line", line)

	// Read command line arguments
	objtype := kmipapi.GetValue(line, "objtype") // example: secretdata

	keymaterial := kmipapi.GetValue(line, "keymaterial")
	if keymaterial == "" {
		fmt.Printf("register key failed, keymaterial is required")
		return
	}

	keyformat := kmipapi.GetValue(line, "keyformat") // example: opaque
	datatype := kmipapi.GetValue(line, "datatype")   // example: Password
	objgrp := kmipapi.GetValue(line, "objgrp")       // example: Password

	attribname1 := kmipapi.GetValue(line, "attribname1")
	attribvalue1 := kmipapi.GetValue(line, "attribvalue1")
	attribname2 := kmipapi.GetValue(line, "attribname2")
	attribvalue2 := kmipapi.GetValue(line, "attribvalue2")
	attribname3 := kmipapi.GetValue(line, "attribname3")
	attribvalue3 := kmipapi.GetValue(line, "attribvalue3")
	attribname4 := kmipapi.GetValue(line, "attribname4")
	attribvalue4 := kmipapi.GetValue(line, "attribvalue4")

	name := kmipapi.GetValue(line, "name")
	if name == "" {
		fmt.Printf("register key failed for name = nil")
	}

	// Execute the Register command
	uid, err := kmipapi.RegisterKey(ctx, settings, keymaterial, keyformat, datatype, objgrp, attribname1, attribvalue1, attribname2, attribvalue2, attribname3, attribvalue3, attribname4, attribvalue4, objtype, name)
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
		fmt.Printf("get attribute uid=value is required, example: get attribute uid=6307 attribname1=x-CustomAttribute4\n")
		return
	}
	attribname1 := kmipapi.GetValue(line, "attribname1")

	uid, err := kmipapi.GetAttribute(ctx, settings, uid, attribname1)
	if err != nil {
		fmt.Printf("get attribute failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("get attribute succeeded for uid (%s)\n", uid)
}
