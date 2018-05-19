package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap"
)

type LDAPAuthenticator struct {
	bindUrl      string
	bindDn       string
	bindPassword string
	queryDn      string

	conn *ldap.Conn
}

func NewLDAPAuthenticator(bindDn, bindPassword, queryDn string) LDAPAuthenticator {
	var authenticator LDAPAuthenticator
	authenticator.bindDn = bindDn
	authenticator.bindPassword = bindPassword
	authenticator.queryDn = queryDn

	return authenticator
}

func (this *LDAPAuthenticator) Connect(bindUrl string) error {
	l, err := ldap.Dial("tcp", bindUrl)
	if err != nil {
		return err
	}

	// Reconnect with TLS
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}

	this.conn = l
	this.bindUrl = bindUrl

	return nil
}

func (this *LDAPAuthenticator) Close() {
	this.conn.Close()
}

func (this LDAPAuthenticator) Authenticate(username, password string) (error, string) {
	err, entry := this.searchForUser(username)
	if err != nil {
		return err, ""
	}

	// Bind as the user to verify their password
	userdn := entry.DN
	err = this.conn.Bind(userdn, password)
	if err != nil {
		return err, ""
	}

	return nil, entry.GetAttributeValue("uid")
}

func (this LDAPAuthenticator) GetUserById(id string) (error, interface{}) {
	return this.searchForUser(id)
}

func (this *LDAPAuthenticator) searchForUser(uid string) (error, *ldap.Entry) {
	if this.bindUrl == "" {
		panic(errors.New("Connect to Server before actually running a Query."))
	}

	// The username and password we want to check
	bindusername := this.bindDn
	bindpassword := this.bindPassword

	// First bind with a read only user
	err := this.conn.Bind(bindusername, bindpassword)
	if err != nil {
		return err, nil
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		this.queryDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", uid),
		[]string{"dn", "uid"},
		nil,
	)

	sr, err := this.conn.Search(searchRequest)
	if err != nil {
		return err, nil
	}

	if len(sr.Entries) != 1 {
		return errors.New("User does not exist or there is technically more than one."), nil
	}

	return nil, sr.Entries[0]
}
