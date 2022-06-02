package local

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestOk(t *testing.T) {
	tmp, err := ioutil.TempFile("", "file")
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	defer os.Remove(tmp.Name())
	r := new(PathReader)
	_, err = r.ReadPath(tmp.Name())
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
}

func TestErr(t *testing.T) {
	r := new(PathReader)
	_, err := r.ReadPath("/path/does/not/exist")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
