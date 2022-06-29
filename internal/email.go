package internal

import (
	"net/smtp"

	"github.com/jordan-wright/email"
)

type EmailSender struct {
	From    string
	Subject string
	Server  string
	Auth    smtp.Auth
}

// Send fulfils interface provider.Sender from github.com/go-pkgz/auth/provider so can be used in
// their verifyProvider as well as in ours messageProvider
func (s *EmailSender) Send(address string, text string) error {
	e := email.NewEmail()
	e.From = s.From
	e.To = []string{address}
	e.Subject = s.Subject
	e.Text = []byte(text)
	return e.Send(s.Server, s.Auth)
}
