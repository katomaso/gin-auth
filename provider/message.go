package provider

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/go-pkgz/rest"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"

	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
)

// PerishibleCache tailored to fit github.com/patrickmn/go-cache
type PerishibleCache interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}, time.Duration)
	Delete(string)
}

type Sender interface {
	Send(address, text string) error
}

// VerifyHandler implements non-oauth2 provider authorizing users with some confirmation.
// can be email, IM or anything else implementing Sender interface
type MessageHandler struct {
	logger.L
	ProviderName string
	TokenService provider.TokenService
	Issuer       string
	// AvatarSaver  provider.AvatarSaver
	Sender      Sender
	Template    string
	UseGravatar bool
	CodeLen     int
	Cache       PerishibleCache
}

// Name of the handler
func (e MessageHandler) Name() string { return e.ProviderName }

// LoginHandler gets an address and sends a confirmation code to it. User is expected to rewrite this
// code manually and send both information to the /auth endpoint. This requres cache on backend side
func (e MessageHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var (
		address string
		buf     bytes.Buffer
	)
	address = r.URL.Query().Get("address")
	if address == "" {
		rest.SendErrorJSON(w, r, e.L, http.StatusBadRequest, errors.New("wrong request"), "can't get user address")
		return
	}
	cid := code(e.CodeLen)
	e.Cache.Set(address, cid, 10*time.Minute)

	tmpl := msgTemplate
	if e.Template != "" {
		tmpl = e.Template
	}
	msgTmpl, err := template.New("confirm").Parse(tmpl)
	if err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "can't parse message template")
		return
	}
	tmplData := struct {
		Address string
		Code    string
		Site    string
	}{
		Address: address,
		Code:    cid,
		Site:    r.URL.Host,
	}

	if err = msgTmpl.Execute(&buf, tmplData); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "can't execute message template")
		return
	}

	if err := e.Sender.Send(address, buf.String()); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to send the message")
		return
	}

	rest.RenderJSON(w, rest.JSON{"address": address, "message": "code sent"})
}

// AuthHandler doesn't do anything for direct login as it has no callbacks
func (e MessageHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	// GET /login?address=someone@example.com&code=1234
	var (
		address, code string
		err           error
	)
	address = r.URL.Query().Get("address")
	if address == "" {
		rest.SendErrorJSON(w, r, e.L, http.StatusBadRequest, errors.New("wrong request"), "address is missing")
		return
	}
	code = r.URL.Query().Get("code")
	if code == "" {
		rest.SendErrorJSON(w, r, e.L, http.StatusBadRequest, errors.New("wrong request"), "code is missing")
		return
	}
	if cid, exists := e.Cache.Get(address); !exists || cid.(string) != code {
		rest.SendErrorJSON(w, r, e.L, http.StatusBadRequest, errors.New("wrong request"), "wrong code")
		return
	}
	e.Cache.Delete(address) // delete the used code

	u := token.User{
		ID:    e.ProviderName + "_" + token.HashID(sha1.New(), address),
		Email: address,
	}
	// try to get gravatar for email
	if e.UseGravatar && strings.Contains(address, "@") { // TODO: better email check to avoid silly hits to gravatar api
		if picURL, err := avatar.GetGravatarURL(address); err == nil {
			u.Picture = picURL
		}
	}
	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Id:       u.ID,
			Issuer:   e.Issuer,
			Audience: "",
		},
		SessionOnly: false,
	}

	if _, err = e.TokenService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}
	// TODO: use next
	// if confClaims.Handshake != nil && confClaims.Handshake.From != "" {
	// 	http.Redirect(w, r, confClaims.Handshake.From, http.StatusTemporaryRedirect)
	// 	return
	// }
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// LogoutHandler - GET /logout
func (e MessageHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	e.TokenService.Reset(w)
}

func code(len int) string {
	bs := make([]byte, len)
	rand.Read(bs)
	for i, b := range bs {
		bs[i] = '0' + (b % 9) // only numbers (ASCII code 48 is )
	}
	return string(bs)
}

var msgTemplate = `
Confirmation for {{.User}} {{.Address}}, site {{.Site}}

Token: {{.Token}}
`
