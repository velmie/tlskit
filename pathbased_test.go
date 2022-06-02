package tlskit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

type readValue struct {
	data []byte
	err  error
}

type mockReader struct {
	values map[string]readValue
}

func (s *mockReader) ReadPath(path string) ([]byte, error) {
	v, ok := s.values[path]
	if !ok {
		return nil, fmt.Errorf("unextected call mockReader.ReadPath(%q)", path)
	}
	return v.data, v.err
}

type pathBasedProviderTest struct {
	description         string
	reader              PathReader
	create              func(r PathReader) *PathBasedProvider
	path                string
	expectedErr         bool
	expectedErrContains string
}

var (
	pemCertsTests = []pathBasedProviderTest{
		{
			description: "should read path",
			reader: &mockReader{map[string]readValue{
				"/ca.crt": {
					data: []byte(certificateAuthority),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r)
			},
			path:        "ca",
			expectedErr: false,
		},
		{
			description: "should read path with the base base",
			reader: &mockReader{map[string]readValue{
				"/the/base/path/ca.crt": {
					data: []byte(certificateAuthority),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r, WithBasePath("/the/base/path"))
			},
			path:        "ca",
			expectedErr: false,
		},
		{
			description: "should read path with custom extension",
			reader: &mockReader{map[string]readValue{
				"/ca.pub": {
					data: []byte(certificateAuthority),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r, WithCertificateExtension(".pub"))
			},
			path:        "ca",
			expectedErr: false,
		},
		{
			description: "should read path with base path, custom path separator and extension",
			reader: &mockReader{map[string]readValue{
				":base:path:ca.pub": {
					data: []byte(certificateAuthority),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(
					r,
					WithCertificateExtension(".pub"),
					WithPathSeparator(":"),
					WithBasePath(":base:path"),
				)
			},
			path:        "ca",
			expectedErr: false,
		},
		{
			description: "should respect reader error",
			reader: &mockReader{map[string]readValue{
				"/ca.crt": {
					data: nil,
					err:  errors.New("some error"),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r)
			},
			path:                "ca",
			expectedErr:         true,
			expectedErrContains: "some error",
		},
	}

	x509KeyPairTests = []pathBasedProviderTest{
		{
			description: "should read path",
			reader: &mockReader{map[string]readValue{
				"/testing.crt": {
					data: []byte(testingCertificate),
				},
				"/testing.key": {
					data: []byte(testingKey),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r)
			},
			path:        "testing",
			expectedErr: false,
		},
		{
			description: "should read path with the base base",
			reader: &mockReader{map[string]readValue{
				"/the/base/path/testing.crt": {
					data: []byte(testingCertificate),
				},
				"/the/base/path/testing.key": {
					data: []byte(testingKey),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r, WithBasePath("/the/base/path"))
			},
			path:        "testing",
			expectedErr: false,
		},
		{
			description: "should read path with custom key and certificate extensions",
			reader: &mockReader{map[string]readValue{
				"/testing.pub": {
					data: []byte(testingCertificate),
				},
				"/testing.pem": {
					data: []byte(testingKey),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(
					r,
					WithCertificateExtension(".pub"),
					WithKeyExtension(".pem"),
				)
			},
			path:        "testing",
			expectedErr: false,
		},
		{
			description: "should read path with base path, custom path separator and extension",
			reader: &mockReader{map[string]readValue{
				":base:path:testing.pub": {
					data: []byte(testingCertificate),
				},
				":base:path:testing.pem": {
					data: []byte(testingKey),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(
					r,
					WithCertificateExtension(".pub"),
					WithKeyExtension(".pem"),
					WithPathSeparator(":"),
					WithBasePath(":base:path"),
				)
			},
			path:        "testing",
			expectedErr: false,
		},
		{
			description: "should respect reader error (crt read)",
			reader: &mockReader{map[string]readValue{
				"/testing.crt": {
					data: nil,
					err:  errors.New("some error"),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r)
			},
			path:                "testing",
			expectedErr:         true,
			expectedErrContains: "some error",
		},
		{
			description: "should respect reader error (key read)",
			reader: &mockReader{map[string]readValue{
				"/testing.crt": {
					data: []byte(testingCertificate),
				},
				"/testing.key": {
					data: nil,
					err:  errors.New("some error"),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r)
			},
			path:                "testing",
			expectedErr:         true,
			expectedErrContains: "some error",
		},
		{
			description: "private and public key should not match",
			reader: &mockReader{map[string]readValue{
				"/testing.crt": {
					data: []byte(certificateAuthority),
				},
				"/testing.key": {
					data: []byte(testingKey),
				},
			}},
			create: func(r PathReader) *PathBasedProvider {
				return NewPathBasedProvider(r)
			},
			path:                "testing",
			expectedErr:         true,
			expectedErrContains: "private key does not match public key",
		},
	}
)

func TestPathBasedCAPemCerts(t *testing.T) {
	for i, tt := range pemCertsTests {
		meta := fmt.Sprintf("test #%d: %s", i, tt.description)
		p := tt.create(tt.reader)
		_, err := p.CAPemCerts(tt.path)
		if err != nil && !tt.expectedErr {
			t.Errorf("%s\ngot unexpected error: %s", meta, err)
		}
		if err == nil && tt.expectedErr {
			t.Errorf("%s\nexpected error, got nil", meta)
		}
		if err != nil && tt.expectedErr && tt.expectedErrContains != "" {
			if !strings.Contains(err.Error(), tt.expectedErrContains) {
				t.Errorf(
					"%s\ngot unexpected error: %s\nthe error is expected to contain %q",
					meta,
					err,
					tt.expectedErrContains,
				)
			}
		}
	}
}

func TestPathBasedX509KeyPair(t *testing.T) {
	for i, tt := range x509KeyPairTests {
		meta := fmt.Sprintf("test #%d: %s", i, tt.description)
		p := tt.create(tt.reader)
		_, err := p.X509KeyPair(tt.path)
		if err != nil && !tt.expectedErr {
			t.Errorf("%s\ngot unexpected error: %s", meta, err)
		}
		if err == nil && tt.expectedErr {
			t.Errorf("%s\nexpected error, got nil", meta)
		}
		if err != nil && tt.expectedErr && tt.expectedErrContains != "" {
			if !strings.Contains(err.Error(), tt.expectedErrContains) {
				t.Errorf(
					"%s\ngot unexpected error: %s\nthe error is expected to contain %q",
					meta,
					err,
					tt.expectedErrContains,
				)
			}
		}
	}
}

const (
	certificateAuthority = `-----BEGIN CERTIFICATE-----
MIIDiTCCAnGgAwIBAgIUPLM5Fcwr5wFsOzEV8x1SMX3iYMAwDQYJKoZIhvcNAQEL
BQAwVDELMAkGA1UEBhMCVFMxDTALBgNVBAgMBFRlc3QxEzARBgNVBAcMClRlc3Rp
bmd0b24xEDAOBgNVBAoMB1Rlc3RpbmcxDzANBgNVBAMMBnRsc2tpdDAeFw0yMjAz
MjIxNzE1NTZaFw0yMzAzMjIxNzE1NTZaMFQxCzAJBgNVBAYTAlRTMQ0wCwYDVQQI
DARUZXN0MRMwEQYDVQQHDApUZXN0aW5ndG9uMRAwDgYDVQQKDAdUZXN0aW5nMQ8w
DQYDVQQDDAZ0bHNraXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4
5snUj1fa40yuJrRcf7bIFpYT8NqkGwfYcW14XyKWhZtO5vRzWeL+JIesLqvHyCXB
YzCjpdcKEaj7ie2yqael/yIZSvvy7OchslPXR696VG4Kyw3v3El8f9b9hdgjZnrv
ednmHoHvC3wGYSEPnUlKgxZnDz46PQMed1cH1S/88KMNBggtkmvqwb3Ue+Dj/Nb5
No/6jtMzvE0oXn+4/+Ze7ZNviw5rA67PPWhAMh9lWyu+ofXY53P+8lbR2+z5grZx
31pB+Yenh9U9KIA73jKSDsStEZqUVkDZ07HlUG8Gq//aFFkR7SEn/9XzQ/dlfH+m
baqrudtgzmWAFEgM7REzAgMBAAGjUzBRMB0GA1UdDgQWBBQ70CDaJmJV4c344ReG
GfokBMs+XTAfBgNVHSMEGDAWgBQ70CDaJmJV4c344ReGGfokBMs+XTAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAp7o05q1QdTakJg2ZyBfj+lv7z
XVLJ3V/6KynUtEXq+417kBIXuLu7LhC/CK7kFIo2waic433IIZ/FnYOQj08+3j4C
j0JauerwjHDEJJVHEq+MQkuDZX6gQjfKLGe9lr+L//uLxlUvwITe9UQ+zuDLewkt
OWO6Z0hVBj7uBsl15TSmgO5ID4EWn9V/e461H8S7Gkqz0Ow95CninY6fdePMXuuU
2wijzax8JzedJSC52Ah8qzit4kYy0zbboDyB0I9vx+3fZi8QxidFCb7cWZ/SilKI
uMVyimwfK6VAnX2WyQrE1a5hNj4N0QTz9t8EiBKDKKZWTYkU2rSljyzdvcN/
-----END CERTIFICATE-----`

	testingCertificate = `-----BEGIN CERTIFICATE-----
MIIDjDCCAnSgAwIBAgIUCt8WKvnyfKr7TvL3Y9sNiS5hr80wDQYJKoZIhvcNAQEL
BQAwVDELMAkGA1UEBhMCVFMxDTALBgNVBAgMBFRlc3QxEzARBgNVBAcMClRlc3Rp
bmd0b24xEDAOBgNVBAoMB1Rlc3RpbmcxDzANBgNVBAMMBnRsc2tpdDAeFw0yMjAz
MjIxNzIxNTNaFw0zMjAzMTkxNzIxNTNaMFsxCzAJBgNVBAYTAlRTMQswCQYDVQQI
DAJUUzEQMA4GA1UEBwwHVGVzdGluZzENMAsGA1UECgwEVGVzdDENMAsGA1UECwwE
VGVzdDEPMA0GA1UEAwwGdGxza2l0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwA6c2cCYFWp3vszCxdil2cTbgTcwnQl3vRCF3fEEiyH3IJerQPwyDg5k
XIKai6pPD8r7n4S+EzexCjlOMDOrcl9fsI1fwQNniQY6xCgqqXm13BffFuCW3DqT
CF+TiqNPK05wUoBcoalSj0yV7pug7jnU9WUPIeZOP5346+cvNbEqcZ1hSqbyRGI6
lNSeFxCKkmPl1ln1Et7Q6XQfXn/w9uoUsNGaZ4o4KCQ5kkj4Lgpys4hMMovyaQLO
GVlT80guulySQHo24t8wYR8aTgEotRpeNYinggygzslRAHUgN11ga2JiLoWVeTOr
9RaTUzU0ep600ftU07XeGMFngz+RsQIDAQABo08wTTALBgNVHQ8EBAMCBDAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwKQYDVR0RBCIwIIINZXhhbXBsZS5sb2NhbIIPKi5l
eGFtcGxlLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQAV8uet0ovbsdzbG2M/aKC+
oR/UMNhjUruYtiY5kuiS3u0Ch7etIdB5Vzhk7khiGgf2UGQzMtk1yVW+Wr8lZjyG
zYJUsFgw8SIkcLj6jFU7Ubfjsa0U/31wrdAz58SIlcDW7vReOFtEX/J45iUrwuT1
NFVvROn32zv1l3mP56//uKdfiGrlTR0BZoqdzlbi76Ze7Zv0i8rDj7vH7se117l1
kcnIN1aYK2IMKDMA6XsP+fYrG7QlAALCp+8w+e2y+AMwPHw1TNxgZkQpwxJm9GFs
DYg1iKVJC5Dz0ZMi/5Rhp7nfIgAaB4x1fVdawUMFDgvQmEmwvPNGQfaCkehflwq6
-----END CERTIFICATE-----
`

	testingKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwA6c2cCYFWp3vszCxdil2cTbgTcwnQl3vRCF3fEEiyH3IJer
QPwyDg5kXIKai6pPD8r7n4S+EzexCjlOMDOrcl9fsI1fwQNniQY6xCgqqXm13Bff
FuCW3DqTCF+TiqNPK05wUoBcoalSj0yV7pug7jnU9WUPIeZOP5346+cvNbEqcZ1h
SqbyRGI6lNSeFxCKkmPl1ln1Et7Q6XQfXn/w9uoUsNGaZ4o4KCQ5kkj4Lgpys4hM
MovyaQLOGVlT80guulySQHo24t8wYR8aTgEotRpeNYinggygzslRAHUgN11ga2Ji
LoWVeTOr9RaTUzU0ep600ftU07XeGMFngz+RsQIDAQABAoIBAQCmN/9oNldpsYuR
hoXL1YU0xDt1yd45C0imSPaS71WPVQYdHycIRzzLDYmuxxoaZnumn3bGyIv49eoz
fwU8knt/sSuQEcsdsWSaItoZiunhY4URx1c85YOrdsZqKM343v5V7L0pqg6Bm5no
i8/3gpn1k/fLqns+S6TNSlt1T9B8Fihxihg7OYvBaTLlg3dy2OVxT7W1t07yMz58
LR/m/nHCcBv1YobyTg8dy2qfugYJIA2xGvdChNsqFZJmbKzWVzudRXjkLrtPfHyS
85yfW1ATmKaiQri5eSQGmcw25HuTFlRgytNdHY/8GeBkABOdHHQ1c4HnUzWNcxpC
/DfhiCABAoGBAO3py9mSfrFhrhg/xV+cVderPZiODoneE6PDJtO/OlC40e8ta7eI
de+QtWZgDd8SmvTjl66C+6kdWg1gpLCU4/qs47tLMoQ7f2+6nFntKogSjznaAYzE
NnBhLYtMbGwUB257bc5gOYCvDJwgNZVORIuRU6Pv5H2K83i5w08ILiaRAoGBAM6o
YC6CtegVqiYqWiTjE9if/sTYTbVmUqXAEPEecu/kG1TJ9VIPS7zgGvIytyLqA22P
DWRJZdWvYkmV+YQWFiF5I4bUK+XKJWvNEohBGbeaofzhFQdCxmKwxxaUi54Bml7g
btFL8i/4irvIma6rGuY2dKDUaumfqppG1/1WmYkhAoGAaZafsDpCHDt75qs2z840
kvke5zv0299B3CZabxOpr/W2xm3kJppbrS0ONRdgUKaTOyhfQ0ZCprWuJ83CidQq
sjBVCeS/0MwPLOknRwnpHGcQRd6pXW4fsxSOAAq0++qPucrx2uv92UzXTdtFrLQF
2+NtuY5YXBd1Ixleww6gXOECgYBhIlszAVUnJSe4kKeWNvWZGHrTYygDX3jxV3mf
G8TCZOFD1TltvKrIuD1yIcxaqMu7r0WIIcevzKPSGqARKaB1U08TjJ6lf4JfTSCs
0oyX9CK3jcQoiYZd1OF/B4soVXCNr8fmsF/BlH0BDqTNqLcYBfiDr9Qgw1+Y7DuR
ZCb+gQKBgCuwHty0O+Er8EOAZsbsC+ajOcRG/uMkKxOGA9ikMd4JT2scE23F1lej
6xxP6ujRDJuU+p6eLo8qfWR6ivUS97Q1Dy5Hpnnm57hrcWuos+5G4TdK9oLrY1Qa
qLK0F6dF2lq4dXm3PU9H/BNXvnNkm942imbYyvls9MXBFEFcuTlg
-----END RSA PRIVATE KEY-----
`
)
