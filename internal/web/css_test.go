package web

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var cssColour = regexp.MustCompile(`(--[a-z-]+):\s*#([0-9a-f]{6});`)

// palette reads the colours of the rule that starts with selector.
func palette(t *testing.T, css, selector string) map[string]string {
	t.Helper()
	start := strings.Index(css, selector+" {")
	if start < 0 {
		t.Fatalf("the stylesheet has no rule %q", selector)
	}
	block := css[start:]
	block = block[:strings.IndexByte(block, '}')]
	colours := map[string]string{}
	for _, m := range cssColour.FindAllStringSubmatch(block, -1) {
		colours[m[1]] = m[2]
	}
	if len(colours) == 0 {
		t.Fatalf("the rule %q sets no colours", selector)
	}
	return colours
}

// luminance is the relative luminance of WCAG 2.
func luminance(t *testing.T, hex string) float64 {
	t.Helper()
	var l float64
	for i, weight := range []float64{0.2126, 0.7152, 0.0722} {
		v, err := strconv.ParseUint(hex[2*i:2*i+2], 16, 8)
		if err != nil {
			t.Fatalf("colour %q: %v", hex, err)
		}
		c := float64(v) / 255
		if c <= 0.04045 {
			c /= 12.92
		} else {
			c = math.Pow((c+0.055)/1.055, 2.4)
		}
		l += weight * c
	}
	return l
}

func contrast(t *testing.T, a, b string) float64 {
	t.Helper()
	la, lb := luminance(t, a), luminance(t, b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// TestContrast holds the palette to WCAG AA in both themes: every colour that text or a state
// mark is drawn in has a contrast of at least 4.5 to 1 against both backgrounds it can sit on.
func TestContrast(t *testing.T) {
	files, _ := loadStatic()
	css := string(files["app.css"].body)
	themes := []struct {
		name     string
		selector string
	}{
		{"light", ":root"},
		{"dark", `:root[data-theme="dark"]`},
	}
	for _, theme := range themes {
		t.Run(theme.name, func(t *testing.T) {
			p := palette(t, css, theme.selector)
			for _, fg := range []string{"--text", "--muted", "--link", "--ok", "--info", "--warn", "--crit"} {
				for _, bg := range []string{"--bg", "--surface"} {
					if p[fg] == "" || p[bg] == "" {
						t.Fatalf("%s or %s is not set", fg, bg)
					}
					if c := contrast(t, p[fg], p[bg]); c < 4.5 {
						t.Errorf("%s #%s on %s #%s: contrast %.2f, want at least 4.5", fg, p[fg], bg, p[bg], c)
					}
				}
			}
			// Borders only have to be visible, not readable.
			if c := contrast(t, p["--line"], p["--surface"]); c < 1.3 {
				t.Errorf("--line on --surface: contrast %.2f, the border disappears", c)
			}
		})
	}
}

// TestDarkThemeTwice keeps the two copies of the dark palette the same: the one for a browser
// that prefers dark, and the one the switch selects.
func TestDarkThemeTwice(t *testing.T) {
	files, _ := loadStatic()
	css := string(files["app.css"].body)
	byPreference := palette(t, css, `:root:not([data-theme="light"])`)
	bySwitch := palette(t, css, `:root[data-theme="dark"]`)
	light := palette(t, css, ":root")
	if len(byPreference) != len(bySwitch) || len(light) != len(bySwitch) {
		t.Errorf("the palettes differ in size: light %d, dark by preference %d, dark by switch %d", len(light), len(byPreference), len(bySwitch))
	}
	for name, colour := range bySwitch {
		if byPreference[name] != colour {
			t.Errorf("%s is #%s by the switch and #%s by the browser's preference", name, colour, byPreference[name])
		}
		if _, ok := light[name]; !ok {
			t.Errorf("%s has no light value", name)
		}
	}
}
