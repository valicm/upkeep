package registry

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLive asks the real registries about the images of the homelab. It needs the network, so
// it only runs with UPKEEP_LIVE=1, and it only checks what stays true as the registries move
// on; what they say is in the log (go test -v).
func TestLive(t *testing.T) {
	if os.Getenv("UPKEEP_LIVE") != "1" {
		t.Skip("set UPKEEP_LIVE=1 to ask the real registries")
	}
	c := New(Options{})
	images := []string{quayImage.image}
	for _, img := range homelab {
		images = append(images, img.image)
	}
	for _, image := range images {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		start := time.Now()
		got := c.Check(ctx, image)
		cancel()
		t.Logf("%s (%s)\n\ttag %q now at %s\n\tnewer: patch %q, minor %q, major %q\n\terror: %q",
			image, time.Since(start).Round(time.Millisecond), got.Tag, got.TagDigest, got.NewerPatch, got.NewerMinor, got.NewerMajor, got.Error)

		ref, err := parseReference(image)
		if err != nil {
			t.Fatalf("parseReference(%q): %v", image, err)
		}
		asked := !ref.local() && ref.tag != ""
		switch {
		case got.Error != "":
			t.Errorf("%s: %s", image, got.Error)
		case asked && !digestRE.MatchString(got.TagDigest):
			t.Errorf("%s: no digest for the tag", image)
		case !asked && (got.TagDigest != "" || got.NewerPatch != "" || got.NewerMinor != "" || got.NewerMajor != ""):
			t.Errorf("%s: something is claimed about an image no registry was asked about: %+v", image, got)
		}
		// Whatever is newer today must still be newer by the rules.
		for _, tag := range []string{got.NewerPatch, got.NewerMinor, got.NewerMajor} {
			if tag == "" {
				continue
			}
			cur, _ := parseTag(ref.tag)
			v, ok := parseTag(tag)
			if !ok || !sameScheme(cur, v) || compareNums(v.nums, cur.nums) < 0 {
				t.Errorf("%s: %q is reported as newer than %q", image, tag, ref.tag)
			}
		}
	}
}
