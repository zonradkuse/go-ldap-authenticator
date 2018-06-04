package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap"
)

type Entry = ldap.Entry

type LDAPAuthenticator struct {
	bindUrl      string
	bindDn       string
	bindPassword string
	queryDn      string
	selectors    []string

	conn *ldap.Conn

	ldapTransformer LDAPTransformer
}

func NewLDAPAuthenticator(bindDn, bindPassword, queryDn string, selectors []string, transformer LDAPTransformer) LDAPAuthenticator {
	var authenticator LDAPAuthenticator
	authenticator.bindDn = bindDn
	authenticator.bindPassword = bindPassword
	authenticator.queryDn = queryDn
	authenticator.selectors = selectors
	authenticator.ldapTransformer = transformer

	return authenticator
}

func (this *LDAPAuthenticator) GetConnection() *ldap.Conn {
	return this.conn
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

	defer this.bindReadUser()

	return nil, entry.GetAttributeValue("uid")
}

func (this LDAPAuthenticator) GetUserById(id string) (error, interface{}) {
	err, entry := this.searchForUser(id)
	if err != nil {
		return err, nil
	}

	return nil, this.ldapTransformer.Transform(entry)
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

	defer this.bindReadUser()

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		this.queryDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", uid),
		append([]string{"dn", "uid"}, this.selectors...),
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

func (this *LDAPAuthenticator) bindReadUser() {
	bindusername := this.bindDn
	bindpassword := this.bindPassword

	this.conn.Bind(bindusername, bindpassword)
}
