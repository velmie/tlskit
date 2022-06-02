package awsssm

import (
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/pkg/errors"
)

type ParameterStore interface {
	GetParameter(*ssm.GetParameterInput) (*ssm.GetParameterOutput, error)
}

type PathReader struct {
	ssmClient ParameterStore
}

func NewPathReader(ssmClient ParameterStore) *PathReader {
	return &PathReader{ssmClient}
}

func (r *PathReader) ReadPath(path string) ([]byte, error) {
	withDecryption := true
	out, err := r.ssmClient.GetParameter(&ssm.GetParameterInput{
		Name:           &path,
		WithDecryption: &withDecryption,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "PathReader: cannot get parameter by name %s", path)
	}
	return []byte(*out.Parameter.Value), nil
}
