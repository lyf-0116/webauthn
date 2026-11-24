package webauthn

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

var _ CredentialStore = (*fakeCredentialStore)(nil)

type fakeCredentialStore struct {
	registeredIDs [][]byte
	err           error
	lookedUpIDs   [][]byte
}

func (store *fakeCredentialStore) CredentialIDExists(credentialID []byte) (bool, error) {
	store.lookedUpIDs = append(store.lookedUpIDs, append([]byte(nil), credentialID...))

	if store.err != nil {
		return false, store.err
	}

	for _, registeredID := range store.registeredIDs {
		if bytes.Equal(registeredID, credentialID) {
			return true, nil
		}
	}

	return false, nil
}

func TestCreateCredential_RejectsDuplicateCredentialID(t *testing.T) {
	body, challenge, credentialID := testRegistrationSpecVectorNoneES256(t)

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
	require.NoError(t, err)

	userID := []byte(testUserID)

	credParams := []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}

	session := SessionData{
		Challenge:  challenge,
		UserID:     userID,
		CredParams: credParams,
	}

	storeErr := errors.New("storage unavailable")

	testCases := []struct {
		name        string
		user        *defaultUser
		store       *fakeCredentialStore
		expectedErr string
		expectedIs  error
		wantLookup  bool
	}{
		{
			name:        "ShouldRejectIDAlreadyOwnedBySameUserWithoutStore",
			user:        &defaultUser{id: userID, credentials: []Credential{{ID: append([]byte(nil), credentialID...)}}},
			expectedErr: "Unable to register credential: the credential id is already registered to this user",
			expectedIs:  ErrCredentialIDAlreadyRegistered,
		},
		{
			name:        "ShouldRejectIDRegisteredToAnotherUser",
			user:        &defaultUser{id: userID},
			store:       &fakeCredentialStore{registeredIDs: [][]byte{append([]byte(nil), credentialID...)}},
			expectedErr: "Unable to register credential: the credential id is already registered to another user",
			expectedIs:  ErrCredentialIDAlreadyRegistered,
			wantLookup:  true,
		},
		{
			name:        "ShouldFailWhenStoreLookupErrors",
			user:        &defaultUser{id: userID},
			store:       &fakeCredentialStore{err: storeErr},
			expectedErr: "Unable to determine whether the credential id is already registered",
			expectedIs:  storeErr,
			wantLookup:  true,
		},
		{
			name:       "ShouldSucceedWhenIDUnknownToStore",
			user:       &defaultUser{id: userID},
			store:      &fakeCredentialStore{registeredIDs: [][]byte{[]byte("a-different-credential-id")}},
			wantLookup: true,
		},
		{
			name: "ShouldSucceedWithoutStoreAndWithoutExistingCredentials",
			user: &defaultUser{id: userID},
		},
		{
			name: "ShouldSucceedWithTypedNilStore",
			user: &defaultUser{id: userID},
			store: func() *fakeCredentialStore {
				var store *fakeCredentialStore

				return store
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				RPID:            "example.org",
				RPOrigins:       []string{"https://example.org"},
				CredentialStore: tc.store,
			}

			w := &WebAuthn{Config: config}

			credential, err := w.CreateCredential(tc.user, session, parsedResponse)

			if tc.expectedErr != "" {
				require.Error(t, err)
				assert.Nil(t, credential)
				assert.EqualError(t, err, tc.expectedErr)
				assert.ErrorIs(t, err, tc.expectedIs)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, credential)
				assert.Equal(t, credentialID, credential.ID)
			}

			if tc.wantLookup {
				require.NotNil(t, tc.store)
				require.Len(t, tc.store.lookedUpIDs, 1)
				assert.Equal(t, credentialID, tc.store.lookedUpIDs[0])
			} else if tc.store != nil {
				assert.Empty(t, tc.store.lookedUpIDs)
			}
		})
	}
}

func TestCreateCredential_DuplicateCheckRunsBeforePersistence(t *testing.T) {
	body, challenge, credentialID := testRegistrationSpecVectorNoneES256(t)

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
	require.NoError(t, err)

	userID := []byte(testUserID)

	config := &Config{
		RPID:      "example.org",
		RPOrigins: []string{"https://example.org"},
		CredentialStore: &fakeCredentialStore{
			registeredIDs: [][]byte{append([]byte(nil), credentialID...)},
		},
	}

	w := &WebAuthn{Config: config}

	session := SessionData{
		Challenge:  challenge,
		UserID:     userID,
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
	}

	credential, err := w.CreateCredential(&defaultUser{id: userID}, session, parsedResponse)

	require.Error(t, err)
	assert.Nil(t, credential)

	var protocolErr *protocol.Error
	require.True(t, errors.As(err, &protocolErr))
	assert.Equal(t, protocol.ErrPolicyRestriction.Type, protocolErr.Type)
	assert.ErrorIs(t, err, ErrCredentialIDAlreadyRegistered)
}
