package ospkg

import (
	"os"
	"strings"
)

// newerKernel returns the newest installed kernel if it is newer than the running one, and ""
// if the machine already runs its newest kernel or nothing can be said.
//
// Only kernels of the running kernel's own kind are compared: its release with every number
// taken out has to be the same. A Raspberry Pi has "6.12.47+rpt-rpi-v8" next to
// "6.12.47+rpt-rpi-2712" and boots only one of them; a container sees the kernel of its host,
// which is no kernel of its own distribution at all.
func newerKernel(root, running string) string {
	if running == "" {
		return ""
	}
	kind, _ := kernelParts(running)
	newest := running
	for _, k := range installedKernels(root) {
		if other, _ := kernelParts(k); other == kind && compareKernels(k, newest) > 0 {
			newest = k
		}
	}
	if newest == running {
		return ""
	}
	return newest
}

// installedKernels lists the kernel releases on disk. /boot/vmlinuz-<release> is where
// Debian, Ubuntu, Raspberry Pi OS and Fedora all put the kernel; /lib/modules is the fallback
// for a /boot that may not be read, and counts only directories that hold a kernel's own
// modules, because a removed kernel can leave a directory of third-party modules behind.
func installedKernels(root string) []string {
	var out []string
	entries, _ := os.ReadDir(root + "/boot")
	for _, e := range entries {
		if release, ok := strings.CutPrefix(e.Name(), "vmlinuz-"); ok && release != "" {
			out = append(out, release)
		}
	}
	if len(out) > 0 {
		return out
	}
	entries, _ = os.ReadDir(root + "/lib/modules")
	for _, e := range entries {
		if _, err := os.Stat(root + "/lib/modules/" + e.Name() + "/kernel"); err == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

// kernelParts splits a release into its kind, the text with "#" for each number, and the
// numbers: "6.12.117+deb13-amd64" is "#.#.#+deb#-amd#" and 6, 12, 117, 13, 64.
func kernelParts(release string) (kind string, numbers []string) {
	var b strings.Builder
	for i := 0; i < len(release); {
		if release[i] < '0' || release[i] > '9' {
			b.WriteByte(release[i])
			i++
			continue
		}
		j := i
		for j < len(release) && release[j] >= '0' && release[j] <= '9' {
			j++
		}
		numbers = append(numbers, strings.TrimLeft(release[i:j], "0"))
		b.WriteByte('#')
		i = j
	}
	return b.String(), numbers
}

// compareKernels compares two releases of the same kind number by number: 6.12.38 is older
// than 6.12.117. Numbers are compared as text, longer first, so none is too large.
func compareKernels(a, b string) int {
	_, an := kernelParts(a)
	_, bn := kernelParts(b)
	for i := 0; i < len(an) && i < len(bn); i++ {
		switch {
		case len(an[i]) != len(bn[i]):
			if len(an[i]) > len(bn[i]) {
				return 1
			}
			return -1
		case an[i] != bn[i]:
			return strings.Compare(an[i], bn[i])
		}
	}
	return 0
}
