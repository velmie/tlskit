# AWS Parameter Store

The package contains the implementation of the `tlskit.PathReader`.
This allows using AWS Parameter Store as a store for certificates.


## Usage example

**In this example, it is assumed that the AWS parameter store stores a certificate by the path `/certificates/ca.crt`.**

```go
package main

import (	
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	
	tlskit "github.com/velmie/tlskit"	
	"github.com/velmie/tlskit/pathreader/awsssm"
	
	"fmt"
	"log"
)

func main() {
	const basePath = "/certificates"

	awsSession, err := session.NewSession()
	if err != nil {
		log.Fatal("cannot create session")
	}
	srv := ssm.New(awsSession, aws.NewConfig().WithRegion("eu-central-1"))

	r := awsssm.NewPathReader(srv)
	p := tlskit.NewPathBasedProvider(r, tlskit.WithBasePath(basePath))

	data, err := p.CAPemCerts("ca")
	if err != nil {
		log.Fatal("cannot get certificate authority", err)
	}
	fmt.Println(string(data))
}

```
