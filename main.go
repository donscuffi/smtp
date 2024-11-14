package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-smtp"
	"io"
	"io/ioutil"
	"log"
	"net"
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

// Session method implementation
func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	fmt.Println("Mail from:", from)
	s.From = from
	return nil
}

// RCPT TO method implementation
func (s *Session) Rcpt(to string) error {
	fmt.Println("Rcpt to:", to)
	s.To = append(s.To, to)
	return nil
}

// DATA method
func (s *Session) Data(r io.Reader) error {
	if data, err := io.ReadAll(r); err != nil {
		return err
	} else {
		fmt.Println("Received message:", string(data))
		for _, recipient := range s.To {
			if err := sendMail(s.From, recipient, data); err != nil {
				fmt.Printf("Failed to send email to %s: %v", recipient, err)
			} else {
				fmt.Println("Sent email to %s successfully", recipient)
			}

		}

		// Processing
		return nil
	}
}

// AUTH method
func (s *Session) AuthPlain(username, password string) error {
	if username != "testuser" || password != "testpass" {
		return fmt.Errorf("Invalid username or password")
	}

	return nil
}

// RSET method
func (s *Session) Logout() error {
	return nil
}

// Lookup
func lookupMX(domain string) ([]*net.MX, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("Error looking up MX records: %v", err)
	}

	return mxRecords, nil
}

// SendMail
func sendMail(from string, to string, data []byte) error {

	for _, mx := range mxRecords {
		host := mx.Host
		for _, port := range []int{25, 587, 465} {

			var b bytes.Buffer
			if err := dkim.Sign(&b, bytes.NewReader(data), dkimOptions); err != nil {
				return fmt.Errorf("Failed to sign email with DKIM: %v", err)
			}
			signedData := b.Bytes()

			// SMTP iteration
			if err = c.Mail(from); err != nil {
				c.Close()
				continue
			}
			if err = c.Rcpt(to); err != nil {
				c.Close()
				continue
			}
			w, err := c.Data()
			if err != nil {
				c.Close()
				continue
			}
			_, err = w.Write(signedData) // Using msg signed with DKIM
			if err != nil {
				c.Close()
				continue
			}
			err = w.Close()
			if err != nil {
				c.Close()
				continue
			}
			c.Quit()
			return nil
		}
	}

	return fmt.Errorf("Failed to send email to %s", to)
}

//	domain := strings.Split(from, "@")[1]
//
//	mxRecords, err := lookupMX(domain)
//	if err != nil {
//		return err
//	}
//
//	for _, mx := range mxRecords {
//		host := mx.Host
//
//		for _, port := range []int{25, 587, 465} {
//			address := fmt.Sprintf("%s:%d", host, port)
//
//			var c *smtp.Client
//
//			var err error
//
//			switch port {
//			case 465:
//				// SMTPS
//				tlsConfig := &tls.Config{ServerName:host}
//				conn, err := tls.Dial("tcp", address, tlsConfig)
//				if err != nil {
//					continue
//				}
//
//				c, err = smtp.NewClient(conn, host)
//
//			case 25, 587:
//				// SMTP or SMTP w/ STARTTLS
//				c, err = smtp.Dial(address)
//				if err != nil {
//					continue
//				}
//
//				if port = 587 {
//					if err = c.StartTLS(&tls.Config{ServerName:host}); err != nil {
//						c.Close()
//						continue
//					}
//				}
//			}
//
//			if err != nil {
//				continue
//			}
//
//			// SMTP iteraction
//			if err = c.Mail(from); err != nil {
//				c.Close()
//
//				continue
//			}
//
//			if err = c.Rcpt(to); err != nil {
//				c.Close()
//				continue
//			}
//
//			w, err := c.Data()
//
//			if err != nil {
//				c.Close()
//				continue
//
//			}
//
//			_, err = w.Write(data)
//			if err != nil {
//				c.Close()
//				continue
//
//			}
//
//			err = w.Close()
//
//			if err != nil {
//				c.Close()
//				continue
//
//			}
//
//			c.Quit()
//
//			return nil
//		}
//	}
//
//	return fmt.Errorf("Failed to send email to %s", to)
//}

// Private DKIM key uploading
var dkimPrivateKey *rsa.PrivateKey

func init() {
	// DKIM key upload from file
	privateKeyPEM, err := ioutil.ReadFile("path/private-key.pem")
	if err != nil {
		log.Fatalf("Failed to read private key: %v", err)
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		log.Fatalf("Failed to parse PEM block conatining private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	dkimPrivateKey = privateKey
}

// DKIM options
var dkimOptions = &dkim.SignOptions{
	Domain:   "example.com",
	Selector: "default",
	Signer:   dkimPrivateKey,
}
