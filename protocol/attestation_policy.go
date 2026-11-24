package protocol

// AttestationPolicy carries the Relying Party policy decisions which §8 of the specification delegates to the
// Relying Party rather than fixing. The zero value selects the most restrictive behavior available for each
// policy it carries.
type AttestationPolicy struct {
	// TrustAnchor configures whether an attestation statement must convey a trust path which can be validated
	// against a trusted anchor. Its zero value selects [TrustAnchorRequired], so an unset policy fails closed.
	TrustAnchor TrustAnchorPolicy

	// AndroidKey configures the Android Key Attestation Statement Format verification procedure.
	AndroidKey AndroidKeyPolicy

	// Compound configures the Compound Attestation Statement Format verification procedure.
	Compound CompoundPolicy
}

// TrustAnchorPolicy selects how attestation verification handles a statement for which no trusted anchor can be
// established.
type TrustAnchorPolicy int

const (
	// TrustAnchorPolicyDefault is the zero value of [TrustAnchorPolicy]. It evaluates as
	// [TrustAnchorRequired] wherever the policy is used.
	TrustAnchorPolicyDefault TrustAnchorPolicy = iota

	// TrustAnchorRequired rejects an attestation unless its format verifier conveys a trust path and the metadata
	// provider validates that path against a trust anchor.
	TrustAnchorRequired

	// TrustAnchorMissingAllowed accepts an attestation which has no validated trust anchor. Such an attestation is
	// marked [AttestationTrustLevelLow]; this is the compatibility tier for legacy authenticators which only use
	// self attestation or otherwise omit an anchor.
	TrustAnchorMissingAllowed
)

// allowMissing returns true only for the explicit compatibility policy. The zero value and every unknown value
// fail closed by requiring an anchor.
func (p TrustAnchorPolicy) allowMissing() bool {
	return p == TrustAnchorMissingAllowed
}

// evaluateTrust maps the result of trust-anchor validation to either a marked trust level or the policy error for
// an unanchored attestation. A validated anchor is always high trust, including when the compatibility policy is set.
func (p AttestationPolicy) evaluateTrust(anchored bool) (AttestationTrustLevel, error) {
	if anchored {
		return AttestationTrustLevelHigh, nil
	}

	if p.TrustAnchor.allowMissing() {
		return AttestationTrustLevelLow, nil
	}

	return "", ErrPolicyRestriction.WithDetails("Attestation verification did not produce a trust anchor accepted by policy").
		WithInfo("Set Attestation.TrustAnchor to TrustAnchorMissingAllowed to accept legacy authenticators without a validated anchor")
}

// AttestationTrustLevel records whether a successfully verified attestation is anchored to a trusted source.
type AttestationTrustLevel string

const (
	// AttestationTrustLevelLow marks a signature-valid attestation for which no trust anchor was validated.
	AttestationTrustLevelLow AttestationTrustLevel = "low"

	// AttestationTrustLevelHigh marks an attestation whose trust path was validated against a trust anchor.
	AttestationTrustLevelHigh AttestationTrustLevel = "high"
)

// AndroidKeyPolicy configures the Android Key Attestation Statement Format verification procedure.
//
// Specification: §8.4. Android Key Attestation Statement Format (https://www.w3.org/TR/webauthn/#sctn-android-key-attestation)
type AndroidKeyPolicy struct {
	// AuthorizationScope selects the authorization lists of the attestation certificate extension which the origin
	// and purpose requirements are evaluated against.
	AuthorizationScope AndroidKeyAuthorizationScope
}

// AndroidKeyAuthorizationScope selects the authorization lists of the Android key attestation certificate
// extension which the §8.4 origin and purpose requirements are evaluated against.
//
// §8.4 assigns this choice to the Relying Party: "For the following, use only the teeEnforced authorization list
// if the RP wants to accept only keys from a trusted execution environment, otherwise use the union of
// teeEnforced and softwareEnforced."
//
// Specification: §8.4. Android Key Attestation Statement Format (https://www.w3.org/TR/webauthn/#sctn-android-key-attestation)
type AndroidKeyAuthorizationScope int

const (
	// AndroidKeyAuthorizationScopeDefault is the zero value of [AndroidKeyAuthorizationScope] and has no matching
	// rule in §8.4. It evaluates as [AndroidKeyAuthorizationScopeTEEEnforced] wherever it is used. webauthn.Config
	// rewrites it to that explicit constant during validation, so a Relying Party can tell an unset field apart
	// from a deliberate choice of the same scope.
	AndroidKeyAuthorizationScopeDefault AndroidKeyAuthorizationScope = iota

	// AndroidKeyAuthorizationScopeTEEEnforced evaluates the origin and purpose requirements against the teeEnforced
	// authorization list alone, accepting only keys generated within a trusted execution environment.
	AndroidKeyAuthorizationScopeTEEEnforced

	// AndroidKeyAuthorizationScopeUnion evaluates the origin and purpose requirements against the union of the
	// teeEnforced and softwareEnforced authorization lists, which additionally accepts software backed keys.
	AndroidKeyAuthorizationScopeUnion
)

// union returns true when the scope evaluates the origin and purpose requirements against both authorization
// lists. Every other value, including the zero value and any value outside the defined set, evaluates them
// against teeEnforced alone so that an unset or malformed policy is the restrictive one.
func (s AndroidKeyAuthorizationScope) union() bool {
	return s == AndroidKeyAuthorizationScopeUnion
}

// CompoundPolicy configures the Compound Attestation Statement Format verification procedure.
//
// Specification: §8.9. Compound Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation)
type CompoundPolicy struct {
	// SubStatementScope selects the sub-statements of the compound attestation which must be verified for the
	// attestation to be accepted.
	SubStatementScope CompoundSubStatementScope
}

// CompoundSubStatementScope selects the sub-statements of a compound attestation which must be verified for the
// attestation to be accepted.
//
// §8.9 assigns this choice to the Relying Party: the handling of a sub-statement which fails verification, and the
// number of sub-statements which must succeed, are matters of Relying Party policy.
//
// The scope applies only to the outcome of the verification procedures. The syntax of the compound statement itself
// is not a matter of policy, so a statement which doesn't satisfy the §8.9 CDDL, nests a compound sub-statement, or
// names a format this library doesn't implement is rejected under every scope.
//
// Specification: §8.9. Compound Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation)
type CompoundSubStatementScope int

const (
	// CompoundSubStatementScopeDefault is the zero value of [CompoundSubStatementScope] and has no matching rule in
	// §8.9. It evaluates as [CompoundSubStatementScopeAll] wherever it is used. webauthn.Config rewrites it to that
	// explicit constant during validation, so a Relying Party can tell an unset field apart from a deliberate choice
	// of the same scope.
	CompoundSubStatementScopeDefault CompoundSubStatementScope = iota

	// CompoundSubStatementScopeAll requires every sub-statement to be verified, and rejects the attestation on the
	// first sub-statement which fails.
	CompoundSubStatementScopeAll

	// CompoundSubStatementScopeAny requires a single sub-statement to be verified, and rejects the attestation only
	// when none of them can be. A sub-statement is verified when its format's verification procedure succeeds and
	// the trust path it produces is accepted by the Metadata Service, so a failure of either is tolerated provided
	// another sub-statement satisfies both.
	CompoundSubStatementScopeAny
)

// any returns true when the scope accepts the attestation on a single verified sub-statement. Every other value,
// including the zero value and any value outside the defined set, requires all of them so that an unset or malformed
// policy is the restrictive one.
func (s CompoundSubStatementScope) any() bool {
	return s == CompoundSubStatementScopeAny
}
