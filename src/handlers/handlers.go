package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/Seagate/kmip-go/src/kmipapi"
)

type CommandHandler func(context.Context, *kmipapi.ConfigurationSettings, string)

var g_handlers map[string]CommandHandler

// Initialize: initialize the list of handlers
func Initialize() {
	g_handlers = map[string]CommandHandler{
		"help":         Help,
		"env":          Env,
		"version":      Version,
		"run":          Run,
		"certs":        Certs,
		"set":          Set,
		"load":         Load,
		"banner":       Banner,
		"open":         Open,
		"close":        Close,
		"discover":     Discover,
		"query":        Query,
		"create":       CreateKey,
		"activate":     ActivateKey,
		"get":          GetKey,
		"locate":       LocateKey,
		"revoke":       RevokeKey,
		"destroy":      DestroyKey,
		"clear":        ClearKey,
		"register":     RegisterKey,
		"getattribute": GetAttribute,
	}
}

// Execute: execute a handler with the text line
func Execute(ctx context.Context, settings *kmipapi.ConfigurationSettings, line string) {
	f, ok := g_handlers[kmipapi.GetCommand(line)]
	if ok {
		start := time.Now()
		f(ctx, settings, line)
		if settings.ShowElapsed {
			duration := time.Since(start)
			fmt.Printf("[elapsed=%s] %s\n", duration, kmipapi.GetCommand(line))
		}

	} else {
		fmt.Printf("No handler for: %s\n", line)
	}
}
