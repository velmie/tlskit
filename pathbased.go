package tlskit

import (
	"crypto/tls"
	"strings"

	"github.com/pkg/errors"
)

const (
	defaultCertificateExtension = ".crt"
	defaultKeyExtension         = ".key"
	defaultPathSeparator        = "/"
)

type PathProviderOptions struct {
	BasePath             string
	PathSeparator        string
	CertificateExtension string
	KeyExtension         string
}

type PathOption func(options *PathProviderOptions)

type PathReader interface {
	ReadPath(path string) ([]byte, error)
}

type PathBasedProvider struct {
	options *PathProviderOptions
	reader  PathReader
}

func NewPathBasedProvider(reader PathReader, options ...PathOption) *PathBasedProvider {
	opts := &PathProviderOptions{
		PathSeparator:        defaultPathSeparator,
		CertificateExtension: defaultCertificateExtension,
		KeyExtension:         defaultKeyExtension,
	}
	for _, option := range options {
		option(opts)
	}
	return &PathBasedProvider{opts, reader}
}

func (p *PathBasedProvider) CAPemCerts(name string) (pemCerts []byte, err error) {
	name = makePath(
		p.options.PathSeparator,
		p.options.BasePath,
		withExtension(name, p.options.CertificateExtension),
	)
	data, err := p.reader.ReadPath(name)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read path %s", name)
	}
	return data, nil
}

func (p *PathBasedProvider) X509KeyPair(name string) (cert tls.Certificate, err error) {
	certPath := makePath(
		p.options.PathSeparator,
		p.options.BasePath,
		withExtension(name, p.options.CertificateExtension),
	)
	certData, err := p.reader.ReadPath(certPath)
	if err != nil {
		return cert, errors.Wrapf(err, "cannot read path %s", certPath)
	}
	keyPath := makePath(
		p.options.PathSeparator,
		p.options.BasePath,
		withExtension(name, p.options.KeyExtension),
	)
	keyData, err := p.reader.ReadPath(keyPath)
	if err != nil {
		return cert, errors.Wrapf(err, "cannot read path %s", keyPath)
	}
	cert, err = tls.X509KeyPair(certData, keyData)
	if err != nil {
		return cert, errors.Wrap(err, "parse a public/private key pair")
	}
	return cert, nil
}

func WithBasePath(basePath string) PathOption {
	return func(options *PathProviderOptions) {
		options.BasePath = basePath
	}
}

func WithPathSeparator(pathSeparator string) PathOption {
	return func(options *PathProviderOptions) {
		options.PathSeparator = pathSeparator
	}
}

func WithCertificateExtension(extension string) PathOption {
	return func(options *PathProviderOptions) {
		options.CertificateExtension = extension
	}
}

func WithKeyExtension(extension string) PathOption {
	return func(options *PathProviderOptions) {
		options.KeyExtension = extension
	}
}

func makePath(separator string, elements ...string) string {
	return strings.Join(elements, separator)
}

func withExtension(name, extension string) string {
	return name + extension
}
