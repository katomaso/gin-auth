# gin-auth

Provides easy to use integration of `github.com/go-pkgz/auth` and `gin-gonic/gin`.

## Usage

```golang
import (
	"github.com/katomaso/gin-auth"
)

func main() {
	router := gin.Default()
	auth := gin_auth.Basic("localhost:8080", "my-app-name", "secret")

	// this needs to be publicaly accessible
	router.Use(auth.Optional())
	router.GET("/auth", auth.AuthHandler())
	router.GET("/avatar", auth.AvatarHandler())

	// after using this middleware, all router will be for authorized users only
	router.Use(auth.Required())
	router.GET("/private", onlyForAuthenticatedUsers)
}
```

If the user is logged in, you will find `c.Get("user")` populated with value of [`go-pkgz/auth/token.User`](https://github.com/go-pkgz/auth/blob/master/token/user.go#L25)
