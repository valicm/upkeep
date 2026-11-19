// upkeep: one binary, two roles. "upkeep agent" runs on a machine and reports what needs
// attention there; "upkeep server" collects those reports, asks appliances through their APIs,
// and shows everything on one dashboard.
package main

import (
	"fmt"
	"os"
	// The time zones travel inside the binary: a minimal container, a Home Assistant app and
	// a firewall need not have them, and a firewall's check time and the mail schedule do.
	_ "time/tzdata"

	"github.com/valicm/upkeep/internal/agent"
	"github.com/valicm/upkeep/internal/server"
	"github.com/valicm/upkeep/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "agent":
		err = agent.Main(os.Args[2:])
	case "server":
		err = server.Main(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version.String())
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "upkeep:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  upkeep agent   [flags]   report this machine's pending updates and backups to a server
  upkeep server  [flags]   collect reports, poll appliances, serve the dashboard
  upkeep version`)
}
