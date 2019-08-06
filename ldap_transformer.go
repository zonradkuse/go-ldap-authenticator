package ldap

// Transformer transforms a ldap Entry to a proper datastructure
type Transformer interface {
	// Transform a single LDAP entry into some data type
	Transform(entry *Entry) interface{}

	// Slectors to use by this Transformer
	Selectors() []string
}
