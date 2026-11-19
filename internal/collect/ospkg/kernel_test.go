package ospkg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewerKernel(t *testing.T) {
	tests := []struct {
		name    string
		boot    []string // /boot/vmlinuz-<release>
		modules []string // /lib/modules/<release>/kernel
		stray   []string // /lib/modules/<release> without a kernel's own modules
		running string
		want    string
	}{
		{
			name: "debian 13", boot: []string{"6.12.38+deb13-cloud-amd64", "6.12.117+deb13-cloud-amd64"},
			running: "6.12.38+deb13-cloud-amd64", want: "6.12.117+deb13-cloud-amd64",
		},
		{
			name: "debian 13, rebooted", boot: []string{"6.12.38+deb13-cloud-amd64", "6.12.117+deb13-cloud-amd64"},
			running: "6.12.117+deb13-cloud-amd64",
		},
		{
			// 6.12.9 is older than 6.12.38: numbers are compared, not text.
			name: "numbers, not text", boot: []string{"6.12.9+deb13-amd64", "6.12.38+deb13-amd64"},
			running: "6.12.38+deb13-amd64",
		},
		{
			name: "debian 12 counts in the middle", boot: []string{"6.1.0-28-amd64", "6.1.0-37-amd64"},
			running: "6.1.0-28-amd64", want: "6.1.0-37-amd64",
		},
		{
			// A Pi has the kernel for each board family installed and boots one of them.
			name:    "raspberry pi, the other board's kernel is not mine",
			boot:    []string{"6.12.47+rpt-rpi-v8", "6.12.62+rpt-rpi-2712", "6.12.47+rpt-rpi-2712"},
			running: "6.12.47+rpt-rpi-v8",
		},
		{
			name:    "raspberry pi, my kernel was updated",
			boot:    []string{"6.12.47+rpt-rpi-v8", "6.12.62+rpt-rpi-v8", "6.12.47+rpt-rpi-2712", "6.12.62+rpt-rpi-2712"},
			running: "6.12.47+rpt-rpi-v8", want: "6.12.62+rpt-rpi-v8",
		},
		{
			// The files of the Fedora 43 workstation the dnf fixtures come from.
			name:    "fedora with its rescue kernel",
			boot:    []string{"0-rescue-35a5eec22b48439eb708b29369f28ed6", "7.2.10-100.fc43.x86_64", "7.2.11-100.fc43.x86_64", "7.2.15-100.fc43.x86_64"},
			running: "7.2.11-100.fc43.x86_64", want: "7.2.15-100.fc43.x86_64",
		},
		{
			name: "cloud kernel next to the generic one", boot: []string{"6.12.38+deb13-cloud-amd64", "6.12.117+deb13-amd64"},
			running: "6.12.38+deb13-cloud-amd64",
		},
		{
			name: "container: the host's kernel is running", boot: []string{"6.12.117+deb13-cloud-amd64"},
			running: "7.2.15-100.fc43.x86_64",
		},
		{
			name: "no /boot to read: the modules tell", modules: []string{"6.1.21-v8+", "6.1.63-v8+"},
			running: "6.1.21-v8+", want: "6.1.63-v8+",
		},
		{
			name: "a removed kernel left third-party modules behind", modules: []string{"6.12.38+deb13-amd64"}, stray: []string{"6.12.117+deb13-amd64"},
			running: "6.12.38+deb13-amd64",
		},
		{
			name: "/boot wins over the modules", boot: []string{"6.12.38+deb13-amd64"}, modules: []string{"6.12.38+deb13-amd64", "6.12.117+deb13-amd64"},
			running: "6.12.38+deb13-amd64",
		},
		{name: "no kernels on disk", running: "6.12.38+deb13-amd64"},
		{name: "running kernel unknown", boot: []string{"6.12.38+deb13-amd64"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			mk := func(path string, dir bool) {
				full := filepath.Join(root, path)
				if dir {
					if err := os.MkdirAll(full, 0o755); err != nil {
						t.Fatal(err)
					}
					return
				}
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, k := range tt.boot {
				mk("/boot/vmlinuz-"+k, false)
				mk("/boot/initrd.img-"+k, false)
			}
			for _, k := range tt.modules {
				mk("/lib/modules/"+k+"/kernel", true)
			}
			for _, k := range tt.stray {
				mk("/lib/modules/"+k+"/updates/dkms", true)
			}
			if got := newerKernel(root, tt.running); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompareKernels(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"6.12.117+deb13-amd64", "6.12.38+deb13-amd64", 1},
		{"6.12.38+deb13-amd64", "6.12.117+deb13-amd64", -1},
		{"6.12.38+deb13-amd64", "6.12.38+deb13-amd64", 0},
		{"6.1.0-37-amd64", "6.1.0-28-amd64", 1},
		{"7.3.4-100.fc43.x86_64", "7.2.15-100.fc43.x86_64", 1},
		{"7.2.15-200.fc44.x86_64", "7.2.15-100.fc43.x86_64", 1},
		{"6.12.007+x", "6.12.7+x", 0},
		{"6.12.99999999999999999999999999+x", "6.12.100000000000000000000000000+x", -1}, // too large for an integer
	}
	for _, tt := range tests {
		if got := compareKernels(tt.a, tt.b); got != tt.want {
			t.Errorf("compare(%s, %s) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestKernelParts(t *testing.T) {
	kind, numbers := kernelParts("6.12.117+deb13-amd64")
	if kind != "#.#.#+deb#-amd#" || len(numbers) != 5 || numbers[2] != "117" {
		t.Errorf("got %q %q", kind, numbers)
	}
}
