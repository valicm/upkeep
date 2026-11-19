// Package e2e runs the real binary from end to end on one machine: "upkeep server" as a
// process of its own, real agents reporting to it, and stand-ins for everything it would
// otherwise reach over the network. It is not part of "go test ./...":
//
//	go test -tags e2e -count=1 -v -timeout 20m ./internal/e2e
//
// What is real: the binary (built here, or UPKEEP_BIN), its configuration files, the HTTP
// between agent and server, SQLite, this machine's package manager, and with Podman at hand
// its containers and a Debian container whose apt reports as a second machine.
//
// What is a stand-in: an OPNsense and a Home Assistant that answer with the connectors' own
// test data, an appliance that accepts a connection and never says a word, and the container
// registries. The server only speaks https to registries and asks no loopback address, so
// the stand-in sits behind a proxy: the server process gets HTTPS_PROXY and a certificate
// authority made here (SSL_CERT_FILE), and every registry it names ends at the stand-in. No
// request about an image leaves the machine.
//
// UPKEEP_E2E_OUT names a directory that gets every page fetched, for reading afterwards.
// UPKEEP_E2E_DEBIAN=0 leaves the Debian container out, UPKEEP_E2E_DEBIAN_IMAGE names another
// image for it. UPKEEP_E2E_LIVE=1 adds the one test that asks the real registries.
package e2e
