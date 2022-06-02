# AWS Secrets Manager

The package contains an implementation of the `tlskit.PathReader`.
This allows using AWS Secrets Manager as a store for certificates.


## Usage example

**In this example, it is assumed that the AWS secrets manager stores a certificate by the path `/certificates/ca.crt`.**

```go
package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	tlskit "github.com/velmie/tlskit"
	"github.com/velmie/tlskit/pathreader/awssecretsmanager"

	"log"
)

func main() {
	const basePath = "/certificates"

	awsSession, err := session.NewSession()
	if err != nil {
		log.Fatal("cannot create session")
	}
	srv := secretsmanager.New(awsSession, aws.NewConfig().WithRegion("eu-central-1"))

	reader := awssecretsmanager.NewPathReader(srv)
	provider := tlskit.NewPathBasedProvider(reader, tlskit.WithBasePath(basePath))

	data, err := provider.CAPemCerts("ca")
	if err != nil {
		log.Fatal("cannot get certificate authority", err)
	}
	fmt.Println(string(data))
}
```
