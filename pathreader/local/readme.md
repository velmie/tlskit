# Local File System

The package contains the implementation of the `tlskit.PathReader`.
The implementation allow to read certificates from a local file system.


## Usage example

```go
package main

import (
	"fmt"
	tlskit "github.com/velmie/tlskit"
	"github.com/velmie/tlskit/pathreader/local"
	"log"
)

func main() {
	const basePath = "/etc/certs"

	r := local.NewPathReader()
	p := tlskit.NewPathBasedProvider(r, tlskit.WithBasePath(basePath))

	data, err := p.CAPemCerts("ca")
	if err != nil {
		log.Fatal("cannot get certificate authority", err)
	}
	fmt.Println(string(data))
}


```
