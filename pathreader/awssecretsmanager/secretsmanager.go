package awssecretsmanager

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
)

type SecretsManager interface {
	GetSecretValue(*secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
}

type PathReader struct {
	secretsManagerClient SecretsManager
}

func NewPathReader(secretsManagerClient SecretsManager) *PathReader {
	return &PathReader{secretsManagerClient}
}

func (r *PathReader) ReadPath(path string) ([]byte, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(path),
	}
	out, err := r.secretsManagerClient.GetSecretValue(input)
	if err != nil {
		return nil, errors.Wrapf(err, "PathReader: cannot get secret value by id %s", path)
	}
	return []byte(*out.SecretString), nil
}
