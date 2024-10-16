package handlers

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/Seagate/kmip-go/pkg/common"
	"github.com/Seagate/kmip-go/src/kmipapi"
	"github.com/fatih/color"
)

func Help(ctx context.Context, connection **tls.Conn, settings *kmipapi.ConfigurationSettings, line string) {
	logger := ctx.Value(common.LoggerKey).(*slog.Logger)
	logger.Debug("Help:", "line", line)

	command := color.New(color.FgWhite).SprintFunc()
	options := color.New(color.FgYellow).SprintFunc()
	comment := color.New(color.FgGreen).SprintFunc()

	col1 := 20
	col2 := 50

	fmt.Println("")
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("help"), col2, options(""), comment("// display this information, [option] indicates optional, key=value pairs"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("env"), col2, options(""), comment("// display all configuration settings"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("run"), col2, options("file=<value>"), comment("// execute all commands contained in a file"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("load"), col2, options("file=<value>"), comment("// load configuration settings from a file"))

	fmt.Printf("  %*s  %-*s  %s\n", col1, command("set"), col2, options("[level=<value>]"), comment("// change the log level error, warn, info, debug"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("set"), col2, options("[ip=<value>] [port=<value>]"), comment("// set the ip and port for the kms server"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("set"), col2, options("[elapsed=<true|false>]"), comment("// set show elapsed to true or false"))

	fmt.Printf("  %*s  %-*s  %s\n", col1, command("version"), col2, options("[major=<value>] [minor=<value>]"), comment("// change the KMIP protocol version"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("certs"), col2, options("[ca=<value>] [key=<value>] [cert=<value>]"), comment("// change the KMS certificate files"))

	fmt.Println("")
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("open"), col2, options("[ip=<value>] [port=<value>]"), comment("// open a TLS session, ip and port are optional"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("close"), col2, options(""), comment("// close the TLS session"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("discover"), col2, options("[major=<value> minor=<value>]"), comment("// discover versions supported by a KMS Server"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("query"), col2, options("[op=<value>]"), comment("// query a KMS Server, operations supported: 1, 3"))

	fmt.Println("")
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("create"), col2, options("id=<value>"), comment("// create a key based on a id, corresponding uid is displayed"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("activate"), col2, options("uid=<value>"), comment("// activate a key based on a uid, returned uid is displayed"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("get"), col2, options("uid=<value>"), comment("// get a key based on a uid, key is displayed"))

	fmt.Println("")
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("locate"), col2, options("id=<value>"), comment("// locate a uid based on a id"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("revoke"), col2, options("uid=<value>"), comment("// revoke a key based on a uid"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("destroy"), col2, options("uid=<value>"), comment("// destroy a key based on a uid"))

	fmt.Printf("  %*s  %-*s  %s\n", col1, command("clear"), col2, options("id=<value>"), comment("// locate, revoke, and destroy a key based on id and uid"))

	fmt.Printf("  %*s  %-*s  %s\n", col1, command("register"), col2, options("type=<value> value=<value>"), comment("// Register a new value"))
}
