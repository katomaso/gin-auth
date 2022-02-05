# gin-auth

Provides easy to use integration of `github.com/go-pkgz/auth` and `gin-gonic/gin`.

## Usage

```golang
import (
	"github.com/katomaso/gin-auth"
)

auth := gin_auth.New(config)

router.Use(auth.Required)
// or 
router.Use(auth.Optional)
```

If the user is logged in, you will find c.Get("user") populated with value of `go-pkgz/auth/token.User`