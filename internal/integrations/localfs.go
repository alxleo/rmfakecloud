package integrations

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ddvk/rmfakecloud/internal/messages"
	"github.com/ddvk/rmfakecloud/internal/model"
	"github.com/google/uuid"
)

const loggerfs = "[localfs] "

type localFS struct {
	rootPath         string
	preserveVersions bool
}

func newLocalFS(i model.IntegrationConfig) *localFS {
	return &localFS{rootPath: i.Path, preserveVersions: i.PreserveVersions}
}

// Existing IDs encode slash-prefixed paths. Retain those IDs while converting
// to os.Root-relative paths; os.Root also confines symbolic links.
func localPath(id string) (string, error) {
	if id == rootFolder {
		return ".", nil
	}
	decoded, err := decodeName(id)
	if err != nil {
		return "", err
	}
	name := strings.TrimPrefix(decoded, "/")
	if name == "" {
		name = "."
	}
	if !filepath.IsLocal(filepath.FromSlash(name)) {
		return "", fmt.Errorf("invalid integration path")
	}
	return name, nil
}

func (d *localFS) GetMetadata(fileID string) (*messages.IntegrationMetadata, error) {
	name, err := localPath(fileID)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(d.rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	stat, err := root.Stat(name)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("not a file")
	}
	ext := path.Ext(name)
	contentType := contentTypeFromExt(ext)
	return &messages.IntegrationMetadata{ID: fileID, Name: path.Base(name), Thumbnail: []byte{}, SourceFileType: contentType, ProvidedFileType: contentType, FileType: strings.TrimPrefix(ext, ".")}, nil
}

func (d *localFS) List(folder string, depth int) (*messages.IntegrationFolder, error) {
	start, err := localPath(folder)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(d.rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	response := messages.NewIntegrationFolder(folder, path.Base(start))
	if start == "." {
		response.Name = "LocalFS root"
	}
	err = visitDir("", path.Clean("/"+start), depth, response, func(name string) ([]fs.FileInfo, error) {
		dir, err := root.Open(strings.TrimPrefix(name, "/"))
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		entries, err := dir.Readdir(-1)
		if err != nil {
			return nil, err
		}
		regular := entries[:0]
		for _, entry := range entries {
			if entry.Mode().IsRegular() || entry.IsDir() {
				regular = append(regular, entry)
			}
		}
		return regular, nil
	})
	return response, err
}

func (d *localFS) Download(fileID string) (io.ReadCloser, int64, error) {
	name, err := localPath(fileID)
	if err != nil {
		return nil, 0, err
	}
	root, err := os.OpenRoot(d.rootPath)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return nil, 0, err
	}
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		file.Close()
		return nil, 0, fmt.Errorf("not a readable file")
	}
	return file, stat.Size(), nil
}

func (d *localFS) Upload(folderID, name, fileType string, reader io.ReadCloser) (string, error) {
	folder, err := localPath(folderID)
	if err != nil {
		return "", err
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") || contentTypeFromExt("."+fileType) == "" {
		return "", fmt.Errorf("invalid export filename")
	}
	root, err := os.OpenRoot(d.rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	stage := path.Join(folder, "."+uuid.NewString()+".part")
	writer, err := root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer root.Remove(stage)
	_, copyErr := io.Copy(writer, reader)
	closeErr := writer.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if d.preserveVersions {
		name += " (" + time.Now().UTC().Format("2006-01-02 15-04-05.000000000") + ")"
	}
	filePath := path.Join(folder, name+"."+fileType)
	if d.preserveVersions {
		// Link publishes the completed file without replacing a prior export.
		err = root.Link(stage, filePath)
	} else {
		err = root.Rename(stage, filePath)
	}
	if err != nil {
		return "", err
	}
	return encodeName("/" + filePath), nil
}
