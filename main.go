package main

import (
	"github.com/emersion/go-smtp"
	"log"
	"time"
)

func main() {
	s := smtp.NewServer(&Backend{})

	s.Addr = ":2525"
	s.Domain = "localhost"
	s.WriteTimeout = 10 * time.Second
	s.ReadTimeout = 10 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true

	log.Println("Starting server", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// Backend of SMTP server
type Backend struct{}

func (bkd *Backend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &Session{}, nil
}

// Session object creation after EHLO command
type Session struct{}
