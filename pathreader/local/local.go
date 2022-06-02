package local

import (
	"os"

	"github.com/pkg/errors"
)

type PathReader struct {
}

func NewPathReader() *PathReader {
	return &PathReader{}
}

func (p *PathReader) ReadPath(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "PathReader: cannot read file by name %s", path)
	}
	return content, nil
}
