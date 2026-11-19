package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/valicm/upkeep/internal/report"
)

// fileBackup reports a backup that shows as files, for appliances that drop theirs on a share.
// The newest file that matches is the latest run. It needs no memory: the files are the record.
func fileBackup(j FileJob) (report.Backup, error) {
	b := report.Backup{Name: j.Name, Kind: "file", MaxAgeHours: j.MaxAgeHours, LastResult: "unknown"}
	files, err := candidates(j.Path)
	if err != nil {
		b.Detail = "could not look for " + j.Path
		return b, fmt.Errorf("backup %s: looking for %s: %w", j.Name, j.Path, err)
	}

	var newest, newestWithData fs.FileInfo
	for _, f := range files {
		if newest == nil || f.ModTime().After(newest.ModTime()) {
			newest = f
		}
		if f.Size() > 0 && (newestWithData == nil || f.ModTime().After(newestWithData.ModTime())) {
			newestWithData = f
		}
	}
	if newestWithData != nil {
		b.LastSuccess = newestWithData.ModTime().UTC()
	}
	switch {
	case newest == nil:
		b.Detail = "no file matches " + j.Path
	case newest.Size() == 0:
		// An appliance that fails half-way tends to leave an empty file. That is a run, and
		// not a backup.
		b.LastRun, b.LastResult = newest.ModTime().UTC(), "failed"
		b.Detail = newest.Name() + " is empty"
	default:
		b.LastRun, b.LastResult = newest.ModTime().UTC(), "ok"
		b.Detail = newest.Name() + ", " + size(newest.Size())
	}
	return b, nil
}

// candidates lists the files a path stands for. A pattern stands for what it matches, and a
// directory for the files in it: one level, because the directory's own time also changes when
// an old backup is deleted and so says nothing.
func candidates(path string) ([]fs.FileInfo, error) {
	matches := []string{path}
	if strings.ContainsAny(path, "*?[") {
		var err error
		if matches, err = filepath.Glob(path); err != nil {
			return nil, fmt.Errorf("the pattern is not valid: %w", err)
		}
	}
	var out []fs.FileInfo
	for _, m := range matches {
		info, err := os.Stat(m)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue // nothing there (yet) is an answer, not a failure
		case err != nil:
			return nil, err
		case info.Mode().IsRegular():
			out = append(out, info)
			continue
		case !info.IsDir():
			continue
		}
		entries, err := os.ReadDir(m)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			// A name with a leading dot is what a transfer in progress is usually given.
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			info, err := os.Stat(filepath.Join(m, e.Name()))
			if err == nil && info.Mode().IsRegular() {
				out = append(out, info)
			}
		}
	}
	return out, nil
}
