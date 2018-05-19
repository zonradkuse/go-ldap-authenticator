package ldap

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/go-ldap/ldap"
)

type LDAPAuthenticator struct {
	bindUrl      string
	bindDn       string
	bindPassword string
	queryDn      string
}

func NewLDAPAuthenticator(bindUrl, bindDn, bindPassword, queryDn string) LDAPAuthenticator {
	var authenticator LDAPAuthenticator
	authenticator.bindUrl = bindUrl
	authenticator.bindDn = bindDn
	authenticator.bindPassword = bindPassword
	authenticator.queryDn = queryDn

	return authenticator
}

func (this *LDAPAuthenticator) Authenticate(username, password string) error {
	// The username and password we want to check
	bindusername := this.bindDn
	bindpassword := this.bindPassword

	l, err := ldap.Dial("tcp", this.bindUrl)
	if err != nil {
		log.Println(err)
		return err
	}
	defer l.Close()

	// Reconnect with TLS
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Println(err)
		return err
	}

	// First bind with a read only user
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Println(err)
		return err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		this.queryDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return err
	}

	if len(sr.Entries) != 1 {
		log.Fatal("User does not exist or too many entries returned")
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		log.Println(err)
		return err
	}

	// Rebind as the read only user for any further queries
	err = l.Bind(bindusername, bindpassword)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil

}
