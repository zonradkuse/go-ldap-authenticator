package ldap

// Transformer transforms a ldap Entry to a proper datastructure
type Transformer interface {
	Transform(entry *Entry) interface{}
}
