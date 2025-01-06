package oauth21

import "strings"

// ScopeStrategy is a strategy for matching scopes.
type ScopeStrategy func(scopes []string, scope string) bool

func HierarchicScopeStrategy(scopes []string, scope string) bool {
	for _, this := range scopes {
		// foo == foo -> true
		if this == scope {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(this) > len(scope) {
			continue
		}

		roles := strings.Split(scope, ".")
		thisRoles := strings.Split(this, ".")
		thisRolesLen := len(thisRoles) - 1
		for i, role := range roles {
			if thisRolesLen < i {
				return true
			}

			current := thisRoles[i]
			if current != role {
				break
			}
		}
	}

	return false
}

func ExactScopeStrategy(scopes []string, scope string) bool {
	for _, this := range scopes {
		if scope == this {
			return true
		}
	}

	return false
}

func WildcardScopeStrategy(matchers []string, scope string) bool {
	scopeParts := strings.Split(scope, ".")
	for _, matcher := range matchers {
		matcherParts := strings.Split(matcher, ".")

		if len(matcherParts) > len(scopeParts) {
			continue
		}

		var notEqual bool
		for k, c := range strings.Split(matcher, ".") {
			// this is the last item and the lengths are different
			if k == len(matcherParts)-1 && len(matcherParts) != len(scopeParts) {
				if c != "*" {
					notEqual = true
					break
				}
			}

			if c == "*" && len(scopeParts[k]) > 0 {
				// pass because this satisfies the requirements
				continue
			} else if c != scopeParts[k] {
				notEqual = true
				break
			}
		}

		if !notEqual {
			return true
		}
	}

	return false
}
