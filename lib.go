package gin_auth

import (
	_ "embed"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/middleware"
	"github.com/go-pkgz/auth/token"
	"github.com/katomaso/gin-auth/internal"
	"github.com/katomaso/gin-auth/provider"
	"github.com/patrickmn/go-cache"
)

//go:embed html/login.html
var loginHTML []byte

type Service struct {
	*auth.Service
	Opts auth.Opts
	m    middleware.Authenticator
	l    logger.L
}

// New constructs auth service with the most basic configuration with params
// - url must be in a full form - it must contain even schema (http or https)
// - appName is used internally as part of JWT token and in other auth places
// - secret is used for signing JWT tokens that are later stored in cookies - keep it really private
func New(url, appName, secret string) *Service {
	if err := os.Mkdir("avatars", os.FileMode(0770)); err != nil {
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
		Logger:         internal.AuthLogger{Logger: log.New(os.Stderr, "[GIN-auth] ", log.Ldate|log.Ltime)},
	}
	return &Service{
		Service: auth.NewService(opts),
		Opts:    opts,
		l:       opts.Logger,
	}
}

func (s *Service) Required() gin.HandlerFunc {
	s.m = s.Middleware()
	return func(c *gin.Context) {
		success := false
		_next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			success = true
			if u, err := token.GetUserInfo(c.Request); err != nil {
				c.Set("user", u)
			}
			c.Next()
		})
		s.m.Auth(_next).ServeHTTP(c.Writer, c.Request)
		if !success {
			c.Abort()
		}
	}
}

func (s *Service) Optional() gin.HandlerFunc {
	s.m = s.Middleware()
	return func(c *gin.Context) {
		_next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, err := token.GetUserInfo(c.Request); err == nil {
				c.Set("user", u)
			}
			c.Next()
		})
		s.m.Trace(_next).ServeHTTP(c.Writer, c.Request)
	}
}

func (s *Service) Index() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Data(200, "text/html", loginHTML)
		return
	}
}

func (s *Service) Providers() gin.HandlerFunc {
	authHandler, _ := s.Handlers()
	return func(c *gin.Context) {
		// TODO
		// if strings.HasPrefix(path, "avatar") {
		// 	avatarProxy.ServeHTTP(c.Writer, c.Request)
		// }
		authHandler.ServeHTTP(c.Writer, c.Request)
	}
}

func (s *Service) AuthHandler() gin.HandlerFunc {
	authHandler, _ := s.Handlers()
	return func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, c.FullPath())
		if path == "" || path == "/" {
			c.Data(200, "text/html", loginHTML)
			return
		}
		authHandler.ServeHTTP(c.Writer, c.Request)
	}
}

func (s *Service) AvatarHandler() gin.HandlerFunc {
	_, avatarProxy := s.Handlers()
	return func(c *gin.Context) {
		avatarProxy.ServeHTTP(c.Writer, c.Request)
	}
}

type Credentials struct {
	Username string
	Password string
	Url      string
}

// AddEmailProvider add email provider under "email/" path or panics
func (s *Service) AddEmailProvider(from, subject, msgTmpl string, codeLen int, server string, auth smtp.Auth) {
	s.AddCustomHandler(provider.MessageHandler{
		L:            s.l,
		TokenService: s.Middleware().JWTService,
		Issuer:       s.Opts.Issuer,
		// AvatarSaver:  s.avatarProxy,
		UseGravatar: true,
		Template:    msgTmpl,
		CodeLen:     codeLen, // the length of requested code for confirmation
		Cache:       cache.New(10*time.Minute, 30*time.Minute),
		Sender: &internal.EmailSender{
			From:    from,
			Subject: subject,
			Server:  server,
			Auth:    auth,
		},
	})
}
