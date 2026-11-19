package containers

import "testing"

func TestReference(t *testing.T) {
	const digest = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	cases := []struct {
		in   string // as a runtime shows it
		want string // fully qualified
		repo string
	}{
		// What Docker shows.
		{"gitea/gitea:1.23.6", "docker.io/gitea/gitea:1.23.6", "docker.io/gitea/gitea"},
		{"mariadb:11.4.13", "docker.io/library/mariadb:11.4.13", "docker.io/library/mariadb"},
		{"redis", "docker.io/library/redis:latest", "docker.io/library/redis"},
		{"adguard/adguardhome", "docker.io/adguard/adguardhome:latest", "docker.io/adguard/adguardhome"},
		{"redis@" + digest, "docker.io/library/redis@" + digest, "docker.io/library/redis"},
		{"index.docker.io/library/mongo:7.0.48", "docker.io/library/mongo:7.0.48", "docker.io/library/mongo"},
		{"docker.io/mongo:7.0.48", "docker.io/library/mongo:7.0.48", "docker.io/library/mongo"},

		// What Podman shows is complete already and comes through unchanged.
		{"docker.io/gitea/gitea:1.23.6", "docker.io/gitea/gitea:1.23.6", "docker.io/gitea/gitea"},
		{"docker.io/library/mariadb:11.8.9", "docker.io/library/mariadb:11.8.9", "docker.io/library/mariadb"},
		{"docker.io/photoprism/photoprism:251130", "docker.io/photoprism/photoprism:251130", "docker.io/photoprism/photoprism"},
		{"lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", "lscr.io/linuxserver/unifi-network-application:10.0.162-ls114", "lscr.io/linuxserver/unifi-network-application"},
		{"docker.io/adguard/adguardhome:latest", "docker.io/adguard/adguardhome:latest", "docker.io/adguard/adguardhome"},
		{"docker.io/louislam/uptime-kuma:2", "docker.io/louislam/uptime-kuma:2", "docker.io/louislam/uptime-kuma"},
		{"ghcr.io/stryan/materia@" + digest, "ghcr.io/stryan/materia@" + digest, "ghcr.io/stryan/materia"},
		{"localhost/medimorec-server:current", "localhost/medimorec-server:current", "localhost/medimorec-server"},
		{"docker.io/library/alpine:3.20@" + digest, "docker.io/library/alpine:3.20@" + digest, "docker.io/library/alpine"},

		// A registry is recognised by a dot, a port or a capital letter.
		{"registry.example:5000/team/app:1.2", "registry.example:5000/team/app:1.2", "registry.example:5000/team/app"},
		{"registry.example:5000/app", "registry.example:5000/app:latest", "registry.example:5000/app"},
		{"localhost:5000/app:dev", "localhost:5000/app:dev", "localhost:5000/app"},
		{"MyRegistry/app:1", "MyRegistry/app:1", "MyRegistry/app"},
		{"team/sub/app:1", "docker.io/team/sub/app:1", "docker.io/team/sub/app"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			ref := parseReference(tc.in)
			if got := ref.String(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if ref.repo != tc.repo {
				t.Errorf("repository %q, want %q", ref.repo, tc.repo)
			}
			if again := parseReference(tc.want).String(); again != tc.want {
				t.Errorf("a qualified reference changed when read again: %q", again)
			}
		})
	}
}

func TestImageID(t *testing.T) {
	const id = "sha256:284e08721b32840fd0d20cbd6e4339ac323ab8fb84739269eb5cd86eedf2ca85"
	cases := []struct {
		configured string
		want       bool
	}{
		{id, true},
		{"284e08721b32840fd0d20cbd6e4339ac323ab8fb84739269eb5cd86eedf2ca85", true},
		{"284e08721b32", true},
		{"284e", true}, // Docker takes any prefix that names one image
		{"sha256:284e08721b32", true},
		{"deadbeef", false}, // looks like an ID but is not this image's: a repository named so
		{"redis:6", false},
		{"284e08721b32:latest", false},
		{"", false},
		{"sha256:", false},
	}
	for _, tc := range cases {
		if got := imageID(tc.configured, id); got != tc.want {
			t.Errorf("imageID(%q) = %v, want %v", tc.configured, got, tc.want)
		}
	}
	if imageID("284e", "") {
		t.Error("an unknown image ID matched")
	}
}

func TestInfraImage(t *testing.T) {
	cases := []struct {
		image string
		want  bool
	}{
		{"localhost/podman-pause:5.4.2-1747958400", true},
		{"registry.k8s.io/pause:3.9", true},
		{"k8s.gcr.io/pause:3.5", true},
		{"rancher/mirrored-pause:3.6", true},
		{"docker.io/library/alpine:3.20", false},
		{"docker.io/example/pausemenu:1", false},
		{"ghcr.io/pause/app:1", false},
	}
	for _, tc := range cases {
		if got := infraImage(parseReference(tc.image)); got != tc.want {
			t.Errorf("infraImage(%q) = %v, want %v", tc.image, got, tc.want)
		}
	}
}
