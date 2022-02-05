package gin_auth

import (
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/token"
	"github.com/katomaso/gin-auth/internal"
)

type Service struct {
	*auth.Service
}

func (s *Service) Required() gin.HandlerFunc {
	return func(c *gin.Context) {
		success := false
		_next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			success = true
			if u, err := token.GetUserInfo(c.Request); err != nil {
				c.Set("user", u)
			}
			c.Next()
		})
		m := s.Middleware()
		m.Auth(_next).ServeHTTP(c.Writer, c.Request)
		if !success {
			c.Abort()
		}
	}
}

func (s *Service) Optional() gin.HandlerFunc {
	return func(c *gin.Context) {
		_next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, err := token.GetUserInfo(c.Request); err == nil {
				c.Set("user", u)
			}
			c.Next()
		})
		m := s.Middleware()
		m.Trace(_next).ServeHTTP(c.Writer, c.Request)
	}
}

func (s *Service) AuthHandler() gin.HandlerFunc {
	authHandler, _ := s.Handlers()
	return func(c *gin.Context) {
		authHandler.ServeHTTP(c.Writer, c.Request)
	}
}

func (s *Service) AvatarHandler() gin.HandlerFunc {
	_, avatarProxy := s.Handlers()
	return func(c *gin.Context) {
		avatarProxy.ServeHTTP(c.Writer, c.Request)
	}
}

func Basic(secret, url, appName string) Service {
	if err := os.Mkdir("avatars", fs.ModeDir); err != nil {
		if os.IsPermission(err) {
			panic("Could not create directory to store avatar pictures")
		}
	}

	opts := auth.Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) { // secret key for JWT
			return secret, nil
		}),
		TokenDuration:  time.Minute * 15, // token expires in 15 minutes
		CookieDuration: time.Hour * 24,   // cookie expires in 1 day and will enforce re-login
		Issuer:         appName,
		URL:            url,
		AvatarStore:    avatar.NewLocalFS("./avatars"),
		Logger:         internal.AuthLogger{log.New(os.Stderr, "[GIN-auth] ", log.Ldate|log.Ltime)},
	}
	return Service{
		auth.NewService(opts),
	}
}
