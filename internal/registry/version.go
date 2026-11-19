package registry

import (
	"regexp"
	"strconv"
	"strings"
)

// The rule of this file: a tag is only called newer when it is the same kind of tag as the one
// in use and its numbers are higher. Anything that needs a guess is left out, because an update
// that does not exist is worse on a dashboard than one that is missing.
//
// A tag is read as: leading words from a short list ("version-", "amd64-"), an optional "v",
// numbers joined by dots, and a tail of words joined by dashes. A word of the tail is a
// pre-release mark ("rc1", "beta.2"), a build counter ("ls114", "r3") or, for everything else,
// part of the variant ("alpine", "rootless"). Two tags compare when all of this agrees: the
// same leading words, the same count of numbers, the same kind of first number, the same
// variant and the same kinds of build counter. With or without "v" makes no difference.

// numClass is what the first number of a tag is. A date never compares with a major version:
// photoprism has both "20220121" and "251130", and the first is not the newer one.
type numClass int

const (
	classNone  numClass = iota // not something to compare: a build ID, a short commit hash
	classSmall                 // 1 to 3 digits: a major version, or a two-digit year
	classYear                  // 4 digits of this century: "2026.11.1"
	classDate                  // "251130" or "20251130", held as 20251130
)

// level says how far a newer tag is from the one in use.
type level int

const (
	levelPatch level = iota
	levelMinor
	levelMajor
)

// preRelease is the mark of a tag that is not a release yet.
type preRelease struct {
	word   string // lowercase: "rc", "beta", "nightly"
	num    uint64
	hasNum bool
}

// tagVersion is a tag read as a version.
type tagVersion struct {
	tag     string
	lead    string   // leading words that belong to the scheme: "version-", "arm64v8-"
	v       bool     // written with a "v" before the numbers
	nums    []uint64 // 1.23.6 is {1, 23, 6}
	class   numClass
	variant string // tail words that are neither pre-release nor build counter, joined by "-"
	pre     *preRelease
	kinds   string   // the build counters' names in order: "ls,", "r,ls,"
	builds  []uint64 // and their numbers
}

// leadWords are tag prefixes that say for whom or what a tag is, not which software it is.
// linuxserver.io tags every build as "amd64-<version>" and "version-<version>" too.
var leadWords = map[string]bool{
	"version": true, "release": true,
	"amd64": true, "arm64": true, "arm64v8": true, "arm32v7": true, "arm32v6": true, "arm32v5": true,
	"armhf": true, "armv7": true, "armv6": true, "armel": true, "aarch64": true, "x86_64": true,
	"i386": true, "ppc64le": true, "s390x": true, "riscv64": true,
}

var (
	// buildRE: linuxserver.io counts its builds as "ls114"; Alpine and Bitnami count package
	// revisions as "r3".
	buildRE = regexp.MustCompile(`^(ls|r)([0-9]{1,9})$`)
	// preRE: "rc", "rc1", "rc.1", "beta.2", "SNAPSHOT". A bare "b" means too many things, so it
	// counts only with a number ("b.91" is how AdGuard Home names its betas).
	preRE = regexp.MustCompile(`^(?i:(alpha|beta|rc|pre|preview|dev|nightly|snapshot|unstable|canary|edge|next|test|testing|experimental)(?:\.?([0-9]{1,18}))?|(b)\.?([0-9]{1,18}))$`)
	// isoDateRE: "2024-05-01" would read as the year 2024 in the variant "05-01", and find
	// only the same day of other years.
	isoDateRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[^0-9]|$)`)
)

// preRank orders the pre-release words that have an agreed order. The others (nightly, dev,
// preview) only compare with themselves.
var preRank = map[string]int{"alpha": 1, "beta": 2, "b": 2, "rc": 3}

// parseTag reads a tag as a version. ok is false for tags that are not versions ("latest",
// "stable", "sha-1a2b3c4") and for versions this code does not dare to compare.
func parseTag(tag string) (v tagVersion, ok bool) {
	v.tag = tag
	rest := tag
	for {
		word, after, found := strings.Cut(rest, "-")
		if !found || !leadWords[word] {
			break
		}
		v.lead += word + "-"
		rest = after
	}
	if len(rest) > 1 && (rest[0] == 'v' || rest[0] == 'V') && isDigit(rest[1]) {
		v.v = true
		rest = rest[1:]
	}
	if rest == "" || !isDigit(rest[0]) || isoDateRE.MatchString(rest) {
		return v, false
	}
	for {
		n := 0
		for n < len(rest) && isDigit(rest[n]) {
			n++
		}
		if n > 18 {
			return v, false // does not fit a uint64, and is no version anyway
		}
		num, _ := strconv.ParseUint(rest[:n], 10, 64)
		if len(v.nums) == 0 {
			if v.class, num = classify(rest[:n], num); v.class == classNone {
				return v, false
			}
		}
		v.nums = append(v.nums, num)
		rest = rest[n:]
		if len(rest) < 2 || rest[0] != '.' || !isDigit(rest[1]) {
			break
		}
		rest = rest[1:]
	}
	if rest == "" {
		return v, true
	}
	// The tail: "-alpine", "-rc1-rootless", "-ls114", and also "b1" or ".dev3" without a dash.
	if rest[0] == '-' || rest[0] == '_' || rest[0] == '.' {
		rest = rest[1:]
	}
	var variant []string
	for _, word := range strings.Split(rest, "-") {
		if word == "" {
			return v, false
		}
		if m := buildRE.FindStringSubmatch(word); m != nil {
			n, _ := strconv.ParseUint(m[2], 10, 64)
			v.kinds += m[1] + ","
			v.builds = append(v.builds, n)
			continue
		}
		if m := preRE.FindStringSubmatch(word); m != nil && v.pre == nil {
			name, digits := m[1], m[2]
			if m[3] != "" {
				name, digits = m[3], m[4]
			}
			v.pre = &preRelease{word: strings.ToLower(name)}
			if digits != "" {
				v.pre.num, _ = strconv.ParseUint(digits, 10, 64)
				v.pre.hasNum = true
			}
			continue
		}
		variant = append(variant, word)
	}
	v.variant = strings.Join(variant, "-")
	return v, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// classify says what kind of number starts a tag. A date is returned in its eight-digit form,
// so that "20220121" and "220302" are in the right order.
func classify(digits string, n uint64) (numClass, uint64) {
	validDate := func(yyyymmdd uint64) bool {
		year, month, day := yyyymmdd/10000, yyyymmdd/100%100, yyyymmdd%100
		return year >= 2000 && year <= 2099 && month >= 1 && month <= 12 && day >= 1 && day <= 31
	}
	switch len(digits) {
	case 1, 2, 3:
		return classSmall, n
	case 4:
		if n >= 2000 && n <= 2099 {
			return classYear, n
		}
	case 6:
		if validDate(20000000 + n) {
			return classDate, 20000000 + n
		}
	case 8:
		if validDate(n) {
			return classDate, n
		}
	}
	return classNone, n
}

// sameScheme reports whether tag c can be compared with the tag in use.
func sameScheme(cur, c tagVersion) bool {
	switch {
	case c.lead != cur.lead, len(c.nums) != len(cur.nums), c.class != cur.class,
		c.variant != cur.variant, c.kinds != cur.kinds:
		return false
	case c.pre == nil:
		return true
	case cur.pre == nil:
		return false // pre-releases are only for those who run one
	}
	// From a pre-release, offer the same kind ("nightly" to "nightly") or one of the ordered
	// kinds (beta to rc), not just anything unfinished.
	return c.pre.word == cur.pre.word || (preRank[c.pre.word] > 0 && preRank[cur.pre.word] > 0)
}

// newerThan reports whether c is a later version than the tag in use, and how far away. Both
// must be of the same scheme.
func (c tagVersion) newerThan(cur tagVersion) (level, bool) {
	for i := range c.nums {
		switch {
		case c.nums[i] < cur.nums[i]:
			return 0, false
		case c.nums[i] > cur.nums[i]:
			return [...]level{levelMajor, levelMinor, levelPatch}[min(i, 2)], true
		}
	}
	// The same numbers: what is left is a release after its pre-releases, a later pre-release,
	// or a later build of the same version.
	if cur.pre != nil {
		if c.pre == nil {
			return levelPatch, true
		}
		order, known := comparePre(*c.pre, *cur.pre)
		if !known || order < 0 {
			return 0, false
		}
		if order > 0 {
			return levelPatch, true
		}
	}
	return levelPatch, compareNums(c.builds, cur.builds) > 0
}

// comparePre orders two pre-releases of the same version. known is false when nothing says
// which came first: "rc" against "rc1", "preview" against "beta".
func comparePre(a, b preRelease) (order int, known bool) {
	if ra, rb := preRank[a.word], preRank[b.word]; ra != rb && ra > 0 && rb > 0 {
		return ra - rb, true
	}
	if a.word != b.word && (preRank[a.word] == 0 || preRank[a.word] != preRank[b.word]) {
		return 0, false
	}
	switch {
	case a.hasNum != b.hasNum:
		return 0, false
	case a.num < b.num:
		return -1, true
	case a.num > b.num:
		return 1, true
	}
	return 0, true
}

func compareNums(a, b []uint64) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return len(a) - len(b)
}

// better reports whether a is the tag to show instead of b, when both are newer than the tag
// in use at the same level.
func better(a, b, cur tagVersion) bool {
	if c := compareNums(a.nums, b.nums); c != 0 {
		return c > 0
	}
	if (a.pre == nil) != (b.pre == nil) {
		return a.pre == nil
	}
	if a.pre != nil {
		if ra, rb := preRank[a.pre.word], preRank[b.pre.word]; ra != rb {
			return ra > rb
		}
		if a.pre.num != b.pre.num {
			return a.pre.num > b.pre.num
		}
	}
	if c := compareNums(a.builds, b.builds); c != 0 {
		return c > 0
	}
	// "1.34.0" and "v1.34.0" are the same release: show the spelling of the tag in use.
	return a.v == cur.v && b.v != cur.v
}

// newerTags picks, from every tag of a repository, the newest later versions of the tag in
// use: one that only raises the patch level (or is a later build of the same version), one
// within the same major, and one of a higher major. An empty string means there is none, or
// none this code can be sure of.
func newerTags(current string, tags []string) (patch, minor, major string) {
	cur, ok := parseTag(current)
	if !ok {
		return "", "", ""
	}
	versions := make([]tagVersion, 0, len(tags))
	for _, tag := range tags {
		if v, ok := parseTag(tag); ok {
			versions = append(versions, v)
		}
	}
	best := pickNewer(cur, versions)
	return best[levelPatch], best[levelMinor], best[levelMajor]
}

// pickNewer returns, for each level, the newest of versions that is newer than cur.
func pickNewer(cur tagVersion, versions []tagVersion) (tags [3]string) {
	var best [3]*tagVersion
	for i := range versions {
		c := &versions[i]
		if !sameScheme(cur, *c) {
			continue
		}
		lvl, newer := c.newerThan(cur)
		if newer && (best[lvl] == nil || better(*c, *best[lvl], cur)) {
			best[lvl] = c
		}
	}
	for lvl, v := range best {
		if v != nil {
			tags[lvl] = v.tag
		}
	}
	return tags
}
