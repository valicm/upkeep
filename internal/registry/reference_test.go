package registry

import (
	"strings"
	"testing"
)

const someDigest = "sha256:c32ebfeefe9c65a225f9c034a7049a940e3556a49aed38588cabf8cfd25baace"

// The expected readings are what github.com/distribution/reference v0.6.0 makes of the same
// strings (normalize.go, splitDockerDomain and ParseNormalizedNamed), which Podman and Docker
// both use.
func TestParseReference(t *testing.T) {
	tests := []struct {
		in    string
		want  reference
		api   string // where the registry's API is
		local bool
	}{
		// The images of the homelab.
		{"docker.io/gitea/gitea:1.23.6", reference{"docker.io", "gitea/gitea", "1.23.6", ""}, "registry-1.docker.io", false},
		{"docker.io/library/mariadb:11.4.13", reference{"docker.io", "library/mariadb", "11.4.13", ""}, "registry-1.docker.io", false},
		{"docker.io/photoprism/photoprism:251130", reference{"docker.io", "photoprism/photoprism", "251130", ""}, "registry-1.docker.io", false},
		{"lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", reference{"lscr.io", "linuxserver/unifi-network-application", "10.0.162-ls114", ""}, "lscr.io", false},
		{"docker.io/adguard/adguardhome:latest", reference{"docker.io", "adguard/adguardhome", "latest", ""}, "registry-1.docker.io", false},
		{"docker.io/louislam/uptime-kuma:2", reference{"docker.io", "louislam/uptime-kuma", "2", ""}, "registry-1.docker.io", false},
		{"ghcr.io/stryan/materia@" + someDigest, reference{"ghcr.io", "stryan/materia", "", someDigest}, "ghcr.io", false},
		{"localhost/medimorec-server:current", reference{"localhost", "medimorec-server", "current", ""}, "localhost", true},

		// Docker Hub is the default, and its one-word names live under library/.
		{"mariadb", reference{"docker.io", "library/mariadb", "latest", ""}, "registry-1.docker.io", false},
		{"mariadb:11.4", reference{"docker.io", "library/mariadb", "11.4", ""}, "registry-1.docker.io", false},
		{"gitea/gitea:1.23.6", reference{"docker.io", "gitea/gitea", "1.23.6", ""}, "registry-1.docker.io", false},
		{"docker.io/mariadb:11.4", reference{"docker.io", "library/mariadb", "11.4", ""}, "registry-1.docker.io", false},
		{"index.docker.io/library/mariadb:11.4", reference{"docker.io", "library/mariadb", "11.4", ""}, "registry-1.docker.io", false},
		{"registry-1.docker.io/gitea/gitea:1", reference{"docker.io", "gitea/gitea", "1", ""}, "registry-1.docker.io", false},
		// A first part without a dot or a colon is a user on Docker Hub, not a registry.
		{"myregistry/app:1", reference{"docker.io", "myregistry/app", "1", ""}, "registry-1.docker.io", false},
		// Without a slash a colon starts the tag, never a port.
		{"registry:5000", reference{"docker.io", "library/registry", "5000", ""}, "registry-1.docker.io", false},

		// Registries with ports, addresses, deep paths.
		{"registry.example.com:5000/team/app:v1.2.3", reference{"registry.example.com:5000", "team/app", "v1.2.3", ""}, "registry.example.com:5000", false},
		{"registry.example.com:5000/app", reference{"registry.example.com:5000", "app", "latest", ""}, "registry.example.com:5000", false},
		{"192.0.2.10:5000/app:1", reference{"192.0.2.10:5000", "app", "1", ""}, "192.0.2.10:5000", false},
		{"[2001:db8::1]:5000/app:1", reference{"[2001:db8::1]:5000", "app", "1", ""}, "[2001:db8::1]:5000", false},
		{"ghcr.io/home-assistant/home-assistant:2026.11.1", reference{"ghcr.io", "home-assistant/home-assistant", "2026.11.1", ""}, "ghcr.io", false},
		{"quay.io/prometheus/node-exporter:v1.8.2", reference{"quay.io", "prometheus/node-exporter", "v1.8.2", ""}, "quay.io", false},
		{"gcr.io/a/b/c/d:1", reference{"gcr.io", "a/b/c/d", "1", ""}, "gcr.io", false},
		{"REGISTRY/app:1", reference{"REGISTRY", "app", "1", ""}, "REGISTRY", false},

		// A digest, with a tag or without.
		{"docker.io/gitea/gitea:1.23.6@" + someDigest, reference{"docker.io", "gitea/gitea", "1.23.6", someDigest}, "registry-1.docker.io", false},
		{"mariadb@" + someDigest, reference{"docker.io", "library/mariadb", "", someDigest}, "registry-1.docker.io", false},
		{"registry.example.com:5000/app@" + someDigest, reference{"registry.example.com:5000", "app", "", someDigest}, "registry.example.com:5000", false},

		// Nothing a registry of ours can be asked about.
		{"localhost/app", reference{"localhost", "app", "latest", ""}, "localhost", true},
		{"localhost:5000/app:1", reference{"localhost:5000", "app", "1", ""}, "localhost:5000", true},
		{"127.0.0.1:5000/app:1", reference{"127.0.0.1:5000", "app", "1", ""}, "127.0.0.1:5000", true},
		{"[::1]:5000/app:1", reference{"[::1]:5000", "app", "1", ""}, "[::1]:5000", true},
		{"[::1]/app:1", reference{"[::1]", "app", "1", ""}, "[::1]", true},
		{strings.TrimPrefix(someDigest, "sha256:"), reference{}, "", true}, // an image ID
		{someDigest, reference{}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseReference(tc.in)
			if err != nil {
				t.Fatalf("parseReference(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseReference(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			if got.apiHost() != tc.api {
				t.Errorf("apiHost of %q = %q, want %q", tc.in, got.apiHost(), tc.api)
			}
			if got.local() != tc.local {
				t.Errorf("local of %q = %v, want %v", tc.in, got.local(), tc.local)
			}
		})
	}
}

func TestParseReferenceErrors(t *testing.T) {
	tests := []struct{ in, wantInError string }{
		{"", "empty"},
		{"docker.io/Gitea/gitea:1", "not a repository name"},
		{"gitea/gitea:", "not a tag"},
		{"gitea/gitea:-1", "not a tag"},
		{"gitea/gitea:" + strings.Repeat("x", 129), "not a tag"},
		{"gitea/gitea@sha256:1234", "not a digest"},
		{"gitea/gitea@latest", "not a digest"},
		{"gitea//gitea:1", "not a repository name"},
		{"docker.io/:1", "not a repository name"},
		{"/gitea:1", "not a repository name"},
		{"reg_istry.example.com/app:1", "not a registry"},
		{"registry.example.com:port/app:1", "not a registry"},
		{"https://ghcr.io/stryan/materia:latest", "not a registry"},
		{"ghcr.io/stryan/materia:v1 ", "not a tag"},
		{"docker.io/" + strings.Repeat("a", 256) + ":1", "not a repository name"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			_, err := parseReference(tc.in)
			if err == nil {
				t.Fatalf("parseReference(%q): no error", tc.in)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Errorf("parseReference(%q): error %q does not say %q", tc.in, err, tc.wantInError)
			}
		})
	}
}
