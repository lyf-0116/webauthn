package protocol

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
)

func TestAttestationVerifyAttestationRequiresTrustAnchor(t *testing.T) {
	withFreshAttestationRegistry(t)

	const format = "trust-policy-test-format"

	RegisterAttestationFormat(AttestationFormat(format), func(AttestationObject, []byte, metadata.Provider, AttestationPolicy, SignaturePolicy) (string, []any, error) {
		return string(metadata.BasicSurrogate), nil, nil
	})

	att := AttestationObject{Format: format}

	err := att.VerifyAttestation([]byte("client-data-hash"), nil, AttestationPolicy{}, SignaturePolicy{})
	require.Error(t, err)

	var protoErr *Error
	require.ErrorAs(t, err, &protoErr)
	assert.Equal(t, ErrPolicyRestriction.Type, protoErr.Type)
	assert.Empty(t, att.TrustLevel)

	err = att.VerifyAttestation([]byte("client-data-hash"), nil, testLegacyAttestationPolicy(), SignaturePolicy{})
	require.NoError(t, err)
	assert.Equal(t, AttestationTrustLevelLow, att.TrustLevel)
	assert.Equal(t, string(metadata.BasicSurrogate), att.Type)
}

func TestAttestationVerifyAttestationDoesNotDowngradeMissingFormat(t *testing.T) {
	att := AttestationObject{Format: "missing-format"}

	err := att.VerifyAttestation([]byte("client-data-hash"), nil, testLegacyAttestationPolicy(), SignaturePolicy{})
	require.Error(t, err)
	assert.EqualError(t, err, ErrAttestationFormat.Details)
}

func TestAttestationFormatRelabelTPMAsPackedDoesNotFallbackToSignatureOnly(t *testing.T) {
	pcc := attestationTestUnpackResponse(t, testAttestationTPMResponses[0])
	att := pcc.Response.AttestationObject
	clientDataHash := sha256.Sum256(pcc.Raw.AttestationResponse.ClientDataJSON)

	att.Format = string(AttestationFormatPacked)

	err := att.VerifyAttestation(clientDataHash[:], nil, testLegacyAttestationPolicy(), SignaturePolicy{})
	require.Error(t, err)
}

func TestAttestationVerifyAttestationNoneUsesLowTrustTier(t *testing.T) {
	att := AttestationObject{Format: string(AttestationFormatNone)}

	err := att.VerifyAttestation([]byte("client-data-hash"), nil, AttestationPolicy{}, SignaturePolicy{})
	require.Error(t, err)
	assert.Equal(t, ErrPolicyRestriction.Type, errorType(t, err))

	err = att.VerifyAttestation([]byte("client-data-hash"), nil, testLegacyAttestationPolicy(), SignaturePolicy{})
	require.NoError(t, err)
	assert.Equal(t, AttestationTrustLevelLow, att.TrustLevel)
}

func TestAttestationVerifyAttestationMarksValidatedAnchorHighTrust(t *testing.T) {
	withFreshAttestationRegistry(t)

	aaguid := uuid.New()
	root, rootKey := metadataTestGenerateCertificate(t, "Trust Policy Root", nil, nil)
	leaf, _ := metadataTestGenerateCertificate(t, "Trust Policy Attestn", root, rootKey)

	entry := &metadata.Entry{
		MetadataStatement: metadata.Statement{
			AaGUID:                      aaguid,
			AttestationTypes:            metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
			AttestationRootCertificates: []*x509.Certificate{root},
		},
	}

	mds := metadataTestExtendedProvider(t, map[uuid.UUID]*metadata.Entry{aaguid: entry}, nil,
		memory.WithValidateTrustAnchor(true),
		memory.WithValidateAttestationTypes(true),
	)

	const format = "trust-policy-anchored-format"

	RegisterAttestationFormat(AttestationFormat(format), func(AttestationObject, []byte, metadata.Provider, AttestationPolicy, SignaturePolicy) (string, []any, error) {
		return string(metadata.BasicFull), []any{leaf.Raw}, nil
	})

	att := AttestationObject{
		Format: format,
		AuthData: AuthenticatorData{
			AttData: AttestedCredentialData{AAGUID: aaguid[:]},
		},
	}

	require.NoError(t, att.VerifyAttestation([]byte("client-data-hash"), mds, AttestationPolicy{}, SignaturePolicy{}))
	assert.Equal(t, AttestationTrustLevelHigh, att.TrustLevel)
}

func errorType(t *testing.T, err error) string {
	t.Helper()

	var protoErr *Error
	require.ErrorAs(t, err, &protoErr)

	return protoErr.Type
}
