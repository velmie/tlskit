package tlskit

import "crypto/tls"

type CertificateAuthorityProvider interface {
	CAPemCerts(name string) (pemCerts []byte, err error)
}

type KeyPairProvider interface {
	X509KeyPair(name string) (cert tls.Certificate, err error)
}

type CertificateProvider interface {
	CertificateAuthorityProvider
	KeyPairProvider
}
