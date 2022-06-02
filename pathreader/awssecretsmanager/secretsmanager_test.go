package awssecretsmanager

import (
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

type mockSecretsManager struct {
	out *secretsmanager.GetSecretValueOutput
	err error
}

func (m *mockSecretsManager) GetSecretValue(
	input *secretsmanager.GetSecretValueInput,
) (*secretsmanager.GetSecretValueOutput, error) {
	return m.out, m.err
}

func TestOk(t *testing.T) {
	v := "value"
	out := &secretsmanager.GetSecretValueOutput{
		SecretString: &v,
	}
	store := &mockSecretsManager{out: out}
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
	store := &mockSecretsManager{err: e}

	reader := NewPathReader(store)
	_, err := reader.ReadPath("any")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), e.Error()) {
		t.Fatal("got unexpected error: ", err.Error())
	}
}
