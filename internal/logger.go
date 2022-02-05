package internal

import (
	"log"
)

type AuthLogger struct {
	*log.Logger
}

func (l AuthLogger) Logf(format string, params ...interface{}) {
	l.Printf(format, params...)
}
