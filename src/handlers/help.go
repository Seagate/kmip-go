package handlers

import (
	"context"
	"fmt"

	"github.com/Seagate/kmip-go/src/common"
	"github.com/fatih/color"
	"k8s.io/klog/v2"
)

func Help(ctx context.Context, settings *common.ConfigurationSettings, line string) {
	logger := klog.FromContext(ctx)
	logger.V(2).Info("Help:", "line", line)

	command := color.New(color.FgWhite).SprintFunc()
	options := color.New(color.FgYellow).SprintFunc()
	comment := color.New(color.FgGreen).SprintFunc()

	col1 := 20
	col2 := 50

	fmt.Println("")
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("help"), col2, options(""), comment("// display this information, [option] indicates optional, key=value pairs"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("env"), col2, options(""), comment("// display all configuration settings"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("load"), col2, options("file=<value>"), comment("// execute all commands contained in a file"))

	fmt.Printf("  %*s  %-*s  %s\n", col1, command("version"), col2, options("[major=<value>] [minor=<value>]"), comment("// change the KMIP protocol version"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("certs"), col2, options("[ca=<value>] [key=<value>] [cert=<value>]"), comment("// change the KMS certificate files"))

	fmt.Println("")
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("open"), col2, options("[ip=<value>] [port=<value>]"), comment("// open a TLS session, ip and port are optional"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("close"), col2, options(""), comment("// close the TLS session"))

	fmt.Println("")
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("create"), col2, options("id=<value>"), comment("// create a key based on the id, corresponding uid is displayed"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("activate"), col2, options("uid=<value>"), comment("// activate a key based on the uid, returned uid is displayed"))
	fmt.Printf("  %*s  %-*s  %s\n", col1, command("get"), col2, options("uid=<value>"), comment("// get a key based on the uid, key is displayed"))
}
