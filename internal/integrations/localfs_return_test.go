package integrations

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/stretchr/testify/require"
)

func TestLocalReturnsPreservePayloadAndVersions(t *testing.T) {
	root := t.TempDir()
	local := newLocalFS(model.IntegrationConfig{Path: root, PreserveVersions: true})
	payloads := []string{"%PDF-1.7\noriginal text\nink version one\n%%EOF", "%PDF-1.7\noriginal text\nink version two\n%%EOF"}
	ids := make([]string, 0, 2)
	for _, payload := range payloads {
		id, err := local.Upload("root", "Walkthrough", "pdf", io.NopCloser(strings.NewReader(payload)))
		require.NoError(t, err)
		ids = append(ids, id)
	}
	require.NotEqual(t, ids[0], ids[1])
	for i, id := range ids {
		reader, size, err := local.Download(id)
		require.NoError(t, err)
		bytes, err := io.ReadAll(reader)
		reader.Close()
		require.NoError(t, err)
		require.Equal(t, payloads[i], string(bytes))
		require.Equal(t, int64(len(payloads[i])), size)
	}
	listing, err := local.List("root", 2)
	require.NoError(t, err)
	require.Len(t, listing.Files, 2)
}

func TestLegacyLocalFSNamingAndIDRemainCompatible(t *testing.T) {
	local := newLocalFS(model.IntegrationConfig{Path: t.TempDir()})
	for _, payload := range []string{"first", "second"} {
		id, err := local.Upload("root", "Walkthrough", "pdf", io.NopCloser(strings.NewReader(payload)))
		require.NoError(t, err)
		require.Equal(t, encodeName("/Walkthrough.pdf"), id)
	}
	listing, err := local.List("root", 2)
	require.NoError(t, err)
	require.Len(t, listing.Files, 1)
	require.Equal(t, encodeName("/Walkthrough.pdf"), listing.Files[0].ID)
	reader, _, err := local.Download(listing.Files[0].ID)
	require.NoError(t, err)
	defer reader.Close()
	payload, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "second", string(payload))
}

func TestLocalFSRejectsTraversalAndEscapingSymlinks(t *testing.T) {
	owner := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "private.pdf"), []byte("other owner"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(owner, "escape")))
	require.NoError(t, os.Symlink(filepath.Join(outside, "private.pdf"), filepath.Join(owner, "private.pdf")))
	local := newLocalFS(model.IntegrationConfig{Path: owner, PreserveVersions: true})
	for _, path := range []string{"/../private.pdf", "../../private.pdf", "/escape/private.pdf", "/private.pdf"} {
		t.Run(path, func(t *testing.T) {
			_, _, err := local.Download(encodeName(path))
			require.Error(t, err)
			_, err = local.GetMetadata(encodeName(path))
			require.Error(t, err)
		})
	}
	for _, folder := range []string{"/../", "/escape"} {
		_, err := local.List(encodeName(folder), 2)
		require.Error(t, err)
		_, err = local.Upload(encodeName(folder), "new", "pdf", io.NopCloser(strings.NewReader("ink")))
		require.Error(t, err)
	}
	for _, name := range []string{"../outside", "folder/file", "folder\\file"} {
		_, err := local.Upload("root", name, "pdf", io.NopCloser(strings.NewReader("ink")))
		require.Error(t, err)
	}
	listing, err := local.List("root", 2)
	require.NoError(t, err)
	require.Empty(t, listing.Files)
	require.Empty(t, listing.SubFolders)
}

type brokenExport struct{}

func (brokenExport) Read([]byte) (int, error) { return 0, errors.New("interrupted export") }

func TestFailedLocalExportDoesNotPublishOrReplace(t *testing.T) {
	root := t.TempDir()
	local := newLocalFS(model.IntegrationConfig{Path: root, PreserveVersions: true})
	_, err := local.Upload("root", "Walkthrough", "pdf", io.NopCloser(brokenExport{}))
	require.Error(t, err)
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, entries)
}
