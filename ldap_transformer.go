package ldap

// LDAPTransformer transforms a ldap Entry to a proper datastructure
type LDAPTransformer interface {
	Transform(entry *Entry) interface{}
}
