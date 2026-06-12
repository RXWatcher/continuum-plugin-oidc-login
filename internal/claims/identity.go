package claims

// Identity is the normalized subject/email/display-name triple derived from a
// claim set. It is the single source of truth for how ExchangeCode (real
// logins) and the admin claim simulator turn raw claims into the identity the
// host receives — keeping the two paths from drifting.
type Identity struct {
	Subject     string
	Email       string
	DisplayName string
}

// DeriveIdentity extracts sub/email and a best-effort display name from a claim
// map. DisplayName prefers "name", then "given_name"+"family_name"
// combinations, and finally falls back to the email.
func DeriveIdentity(c map[string]any) Identity {
	sub, _ := c["sub"].(string)
	email, _ := c["email"].(string)
	name, _ := c["name"].(string)
	if name == "" {
		first, _ := c["given_name"].(string)
		last, _ := c["family_name"].(string)
		switch {
		case first != "" && last != "":
			name = first + " " + last
		case first != "":
			name = first
		case last != "":
			name = last
		default:
			name = email
		}
	}
	return Identity{Subject: sub, Email: email, DisplayName: name}
}

// EmailVerified reports whether c carries email_verified == true. The bool
// second return reports whether the claim was present at all (for diagnostics).
func EmailVerified(c map[string]any) (verified, found bool) {
	v, found := c["email_verified"]
	b, ok := v.(bool)
	return ok && b, found
}
