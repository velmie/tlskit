package awsssm

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/pkg/errors"
)

type mockParameterStore struct {
	err error
	out *ssm.GetParameterOutput
}

func (m *mockParameterStore) GetParameter(input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
	return m.out, m.err
}

func TestOk(t *testing.T) {
	v := "value"
	out := &ssm.GetParameterOutput{Parameter: &ssm.Parameter{
		Value: &v,
	}}
	store := &mockParameterStore{out: out}
	reader := NewPathReader(store)

	got, err := reader.ReadPath("any")
	if err != nil {
		t.Fatal("got unexpected error: ", err.Error())
	}
	if v != string(got) {
		t.Errorf("got unexpected result:\nexpected %q, got %q", v, string(got))
	}
}

func TestErr(t *testing.T) {
	e := errors.New("something went wrong")
	store := &mockParameterStore{err: e}

	reader := NewPathReader(store)
	_, err := reader.ReadPath("any")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), e.Error()) {
		t.Fatal("got unexpected error: ", err.Error())
	}
}
