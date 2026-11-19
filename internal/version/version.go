// Package version holds the build's version, set with -ldflags "-X ...version.Version=1.2.3".
package version

import "runtime"

// Version is "dev" for a build that was not released.
var Version = "dev"

// String is what "upkeep version" prints and what an agent sends as its version.
func String() string { return Version + " " + runtime.GOOS + "/" + runtime.GOARCH }
