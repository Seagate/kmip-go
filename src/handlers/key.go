package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/Seagate/kmip-go/kmip14"
	"github.com/Seagate/kmip-go/pkg/common"
	"github.com/Seagate/kmip-go/src/kmipapi"
)

//
// This file contains command line handlers for various operations. They call a common layer of KMIP commands that
// supports various KMIP Protocol versions. These commands use fmt.Printf() calls since we want the 'kms' tool user
// to see the results.
//

// CreateKey: usage 'create id=<value>' to create a new kmip cryptographic key
func CreateKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("CreateKey", "line", line)

	id := kmipapi.GetValue(line, "id")
	if id == "" {
		fmt.Printf("create id=value is required, example: create id=ZAD0YA320000C7300BYS\n")
		return
	}

	uid, err := kmipapi.CreateKey(ctx, *connection, settings, id)
	if err != nil {
		fmt.Printf("create key failed for id (%s) with error: %v\n", id, err)
		return
	}

	// Store the returned uid in ${lastuid} for use in other commands with that variable
	kmipapi.SetValue(kmipapi.LastUID, uid)

	fmt.Printf("key created for id (%s) returned uid (%s)\n", id, uid)
}

// ActivateKey: usage 'activate uid=<value>' to activate unique identifier
func ActivateKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("ActivateKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("activate uid=value is required, example: activate uid=6201\n")
		return
	}

	uid, err := kmipapi.ActivateKey(ctx, *connection, settings, uid)
	if err != nil {
		fmt.Printf("activate key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("key activated for uid (%s)\n", uid)
}

// GetKey: usage 'get uid=<value>' to retrieve kmip cryptographic key material
func GetKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("GetKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")

	if uid == "" {
		fmt.Printf("get uid=value is required, example: get uid=6201\n")
		return
	}

	_, err := kmipapi.GetKey(ctx, *connection, settings, uid)
	if err != nil {
		fmt.Printf("get key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("get key for uid (%s)\n", uid)
}

// LocateKey: usage 'locate id=<value>' to return the uid of the id, where id is required
func LocateKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("LocateKey", "line", line)

	id := kmipapi.GetValue(line, "id")
	attribname1 := kmipapi.GetValue(line, "attribname1")
	attribvalue1 := kmipapi.GetValue(line, "attribvalue1")
	attribname2 := kmipapi.GetValue(line, "attribname2")
	attribvalue2 := kmipapi.GetValue(line, "attribvalue2")

	if id == "" && attribvalue2 == "" {
		fmt.Printf("locate id, attribname2, and attribvalue2 are required, example: locate id=SASED-M-2-14-name attribname2=ObjectType attribvalue2=SecretData\n")
		return
	}

	uid, err := kmipapi.LocateUid(ctx, *connection, settings, id, attribname1, attribvalue1, attribname2, attribvalue2)
	if err != nil {
		fmt.Printf("locate failed for id (%s) with error: %v\n", id, err)
		return
	}

	// Store the returned uid in ${lastuid} for use in other commands with that variable
	kmipapi.SetValue(kmipapi.LastUID, uid)

	fmt.Printf("locate key for id (%s) returned uid (%s)\n", id, uid)
}

// RevokeKey: usage 'revoke uid=<value>' to revoke a key based on uid
func RevokeKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("RevokeKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("revoke uid=value is required, example: revoke id=6307\n")
		return
	}

	uid, err := kmipapi.RevokeKey(ctx, *connection, settings, uid, uint32(kmip14.RevocationReasonCodeCessationOfOperation))

	if err != nil {
		fmt.Printf("revoke key failed for uid (%s) with error: %v\n", uid, err)
	} else {
		fmt.Printf("revoke key succeeded for uid (%s)\n", uid)
	}
}

// DestroyKey: usage 'destroy uid=<value>' to destroy a key based on uid
func DestroyKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("DestroyKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("destroy uid=value is required, example: destroy id=6307\n")
		return
	}

	uid, err := kmipapi.DestroyKey(ctx, *connection, settings, uid)
	if err != nil {
		fmt.Printf("destroy key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("destroy key succeeded for uid (%s)\n", uid)
}

// ClearKey: usage 'clear id=<value>' to locate, revoke, and destroy a key based on id and uid
func ClearKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("ClearKey", "line", line)

	id := kmipapi.GetValue(line, "id")
	if id == "" {
		fmt.Printf("clear id=value is required, example: clear id=DISK01234\n")
		return
	}

	success := true

	uid, err := kmipapi.LocateUid(ctx, *connection, settings, id, "", "", "", "")
	if err != nil || uid == "" {
		fmt.Printf("locate failed for id (%s), uid (%s), error: %v\n", id, uid, err)
		success = false
	} else {
		fmt.Printf("locate key for id (%s) returned uid (%s)\n", id, uid)
		fmt.Printf("\n")

		uid, err = kmipapi.RevokeKey(ctx, *connection, settings, uid, uint32(kmip14.RevocationReasonCodeCessationOfOperation))
		if err != nil {
			fmt.Printf("revoke key failed for uid (%s) with error: %v\n", uid, err)
			success = false
		} else {
			fmt.Printf("revoke key succeeded for uid (%s)\n", uid)
		}
		fmt.Printf("\n")

		uid, err = kmipapi.DestroyKey(ctx, *connection, settings, uid)
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
func RegisterKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Register:", "line", line)

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
	uid, err := kmipapi.RegisterKey(ctx, *connection, settings, keymaterial, keyformat, datatype, objgrp, attribname1, attribvalue1, attribname2, attribvalue2, attribname3, attribvalue3, attribname4, attribvalue4, objtype, name)
	if err != nil {
		fmt.Printf("register key failed with error: %v\n", err)
		return
	}
	fmt.Printf("register key succeeded for uid (%s)\n", uid)
}

// GetAttribute: Return the Attribute details based on uid and attribute name
func GetAttribute(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("GetAttribute", "line", line)

	uid := kmipapi.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("get attribute uid=value is required, example: get attribute uid=6307 attribname1=x-CustomAttribute4\n")
		return
	}
	attribname1 := kmipapi.GetValue(line, "attribname1")

	resp, err := kmipapi.GetAttribute(ctx, *connection, settings, uid, attribname1)
	if err != nil {
		fmt.Printf("get attribute failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("get attribute succeeded for uid (%s) with attribute: %v\n", uid, resp)
}

// ReKey: usage 'rekey uid=<value>' to change kmip cryptographic key material
func ReKey(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("ReKey", "line", line)

	uid := kmipapi.GetValue(line, "uid")

	if uid == "" {
		fmt.Printf("rekey uid=value is required, example: get uid=6201\n")
		return
	}

	newuid, err := kmipapi.ReKey(ctx, *connection, settings, uid)
	if err != nil {
		fmt.Printf("rekey key failed for uid (%s) with error: %v\n", uid, err)
		return
	}

	fmt.Printf("rekey key new uid (%s)\n", newuid)
}
