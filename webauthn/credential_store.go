package webauthn

import (
	"errors"

	"github.com/go-webauthn/webauthn/protocol"
)

// ErrCredentialIDAlreadyRegistered is returned by [WebAuthn.CreateCredential] when the credential ID returned by a
// registration ceremony is already associated with a credential record, either on the user completing the ceremony
// or, when a [CredentialStore] is configured, on any other user of this Relying Party. A ceremony which fails with
// this error must not be followed by a persistence attempt.
//
// The Relying Party remains responsible for enforcing credential ownership uniqueness atomically at the storage
// layer: this error only reports the registrations the library can observe in advance. See the [CredentialStore]
// documentation for why a unique index is still required in distributed deployments.
var ErrCredentialIDAlreadyRegistered = errors.New("the credential id is already registered")

// CredentialStore is the optional storage hook a Relying Party implements to enforce credential ownership
// uniqueness across every user. It backs the check required by step 17 of the registration ceremony, which asks
// the Relying Party to reject a credential ID that is already registered to another user.
//
// CredentialIDExists reports whether a credential record with the given credential ID already exists for the
// configured Relying Party ID. It must observe every credential the Relying Party persists, not only the
// credentials owned by the user completing the ceremony; a store scoped to one user cannot detect the cross-user
// collision this interface exists to prevent. Returning true makes [WebAuthn.CreateCredential] fail the ceremony
// with [ErrCredentialIDAlreadyRegistered] before a [Credential] is returned.
//
// A non-nil error aborts the ceremony and is wrapped into the returned error unchanged via [errors.Is]/[errors.As].
//
// This is a read-before-write check and, on its own, is not safe against two registration ceremonies racing on the
// same credential ID. The Relying Party MUST additionally place a unique index on the (RP ID, credential ID)
// columns of the credential table and translate the resulting duplicate-key write failure into
// [ErrCredentialIDAlreadyRegistered], so concurrent registrations can never both persist. The Storage section of
// the package documentation shows the recommended index.
//
// Specification: §7.1. Registering a New Credential, step 17
// (https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
type CredentialStore interface {
	CredentialIDExists(credentialID []byte) (exists bool, err error)
}

// validateCredentialIDUnregistered enforces that the credential ID produced by a registration ceremony is not
// already in use. It first checks the credentials owned by the user completing the ceremony, which catches a
// replayed registration without requiring any storage integration, and then consults the optional Relying Party
// wide [CredentialStore] so the same credential ID cannot be registered under a second user.
func validateCredentialIDUnregistered(credentialID []byte, user User, store CredentialStore) error {
	if isCredentialIDInCredentials(credentialID, user.WebAuthnCredentials()) {
		return protocol.ErrPolicyRestriction.WithDetails("Unable to register credential: the credential id is already registered to this user").WithInfo(ErrCredentialIDAlreadyRegistered.Error()).WithError(ErrCredentialIDAlreadyRegistered)
	}

	if isNil(store) {
		return nil
	}

	exists, err := store.CredentialIDExists(credentialID)
	if err != nil {
		return protocol.ErrBadRequest.WithDetails("Unable to determine whether the credential id is already registered").WithInfo(err.Error()).WithError(err)
	}

	if exists {
		return protocol.ErrPolicyRestriction.WithDetails("Unable to register credential: the credential id is already registered to another user").WithInfo(ErrCredentialIDAlreadyRegistered.Error()).WithError(ErrCredentialIDAlreadyRegistered)
	}

	return nil
}
