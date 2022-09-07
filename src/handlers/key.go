package handlers

import (
	"context"
	"fmt"

	"github.com/Seagate/kmip-go/src/common"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"k8s.io/klog/v2"
)

// CreateKey: usage 'create id=<value>' to create a new kmip cryptographic key
func CreateKey(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("CreateKey", "line", line)

	id := common.GetValue(line, "id")
	if id == "" {
		fmt.Printf("create id=value is required, example: create id=ZAD0YA320000C7300BYS\n")
		return
	}

	uid, err := kmipapi.CreateKey(ctx, settings, id)

	if err != nil {
		fmt.Printf("create key failed for id (%s) with error: %v\n", id, err)
	}

	fmt.Printf("key created, uid is %s\n", uid)
}

// ActivateKey: usage 'activate uid=<value>' to activate unique identifier
func ActivateKey(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("ActivateKey", "line", line)

	uid := common.GetValue(line, "uid")
	if uid == "" {
		fmt.Printf("activate uid=value is required, example: activate uid=6201\n")
		return
	}

	uid, err := kmipapi.ActivateKey(ctx, settings, uid)

	if err != nil {
		fmt.Printf("activate key failed for uid (%s) with error: %v\n", uid, err)
	}

	fmt.Printf("key activated, uid is %s\n", uid)
}

// GetKey: usage 'get uid=<value>' to retrieve kmip cryptographic key material
func GetKey(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("GetKey", "line", line)

	uid := common.GetValue(line, "uid")

	if uid == "" {
		fmt.Printf("get uid=value is required, example: get uid=6201\n")
		return
	}

	key, err := kmipapi.GetKey(ctx, settings, uid)

	if err != nil {
		fmt.Printf("get key failed for uid (%s) with error: %v\n", uid, err)
	}

	fmt.Printf("get key for uid %s key is %v\n", uid, key)
}

// LocateKey: usage 'locate id=<value>' to return the uid of the id, where id is required
func LocateKey(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("LocateKey", "line", line)

	id := common.GetValue(line, "id")

	if id == "" {
		fmt.Printf("locate id=value is required, example: locate id=ZAD0YA320000C7300BYS\n")
		return
	}

	uid, err := kmipapi.Locate(ctx, settings, id)

	if err != nil {
		fmt.Printf("locate failed for id (%s) with error: %v\n", id, err)
	}

	fmt.Printf("locate key for id %s returned uid %s\n", id, uid)
}

func DestroyKey(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	fmt.Printf("Destroy: %s\n", line)
}
