//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package alibaba implement the interface with alibaba cloud kms service
package alibaba

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi"
	openapiutil "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi-util"
	"github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	ttlcache "github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, _ crypto.Hash, _ ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID)
	})
}

const (
	cacheKey = "signer"
	// ReferenceScheme schemes for various KMS services
	ReferenceScheme = "alibabakms://"
)

type aliClient struct {
	dkmsClient        *sdk.Client
	endpoint          string
	instanceId        string
	keyId             string
	clientKeyFile     string
	clientKeyPassword string
	caCert            string
	keyCache          *ttlcache.Cache[string, cmk]
}

var (
	errKMSReference = errors.New("kms specification should be in the format alibabakms://[ENDPOINT]/[INSTANCE_ID]/[KEY_ID]")

	keyIDRE = regexp.MustCompile(`^alibabakms://([^/]*)/([^/]*)/([^/]*)$`)
	allREs  = []*regexp.Regexp{keyIDRE}
)

const (
	signingAlgorithmSpecRSA_PSS_SHA_256   = "RSA_PSS_SHA_256"
	signingAlgorithmSpecRSA_PKCS1_SHA_256 = "RSA_PKCS1_SHA_256"
	signingAlgorithmSpecECDSA_SHA_256     = "ECDSA_SHA_256"
	signingAlgorithmSpecSM2DSA            = "SM2DSA"

	masterKeySpecEC_P256  = "EC_P256"
	masterKeySpecEC_P256K = "EC_P256K"
)

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	for _, re := range allREs {
		if re.MatchString(ref) {
			return nil
		}
	}
	return errKMSReference
}

// ParseReference parses an alibabakms-scheme URI into its constituent parts.
func ParseReference(resourceID string) (endpoint, instanceId, keyId string, err error) {
	var v []string
	for _, re := range allREs {
		v = re.FindStringSubmatch(resourceID)
		if len(v) >= 3 {
			endpoint, instanceId = v[1], v[2]
			if len(v) == 4 {
				keyId = v[3]
			}
			return
		}
	}
	err = fmt.Errorf("invalid alibabakms format %q", resourceID)
	return
}

func newAliClient(ctx context.Context, keyResourceID string) (*aliClient, error) {
	if err := ValidReference(keyResourceID); err != nil {
		return nil, err
	}
	a := &aliClient{}
	var err error
	a.endpoint, a.instanceId, a.keyId, err = ParseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	a.keyCache = ttlcache.New[string, cmk](
		ttlcache.WithDisableTouchOnHit[string, cmk](),
	)

	return a, nil
}

func (a *aliClient) setupClient(ctx context.Context) error {
	config := &openapi.Config{
		Protocol:      tea.String("https"),
		Endpoint:      tea.String(a.endpoint),
		ClientKeyFile: tea.String(a.clientKeyFile),
		Password:      tea.String(a.clientKeyPassword),
	}

	client, err := sdk.NewClient(config)
	if err != nil {
		return err
	}
	a.dkmsClient = client
	return nil
}

type keyMetadata struct {
	SigningAlgorithms []string
}

type cmk struct {
	KeyMetadata keyMetadata
	PublicKey   crypto.PublicKey
}

func (c *cmk) HashFunc() crypto.Hash {
	return crypto.SHA256
}

func (c *cmk) Verifier() (signature.Verifier, error) {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ecdsa")
	}
	return signature.LoadECDSAVerifier(pub, c.HashFunc())
}

func (a *aliClient) fetchCMK(ctx context.Context) (*cmk, error) {
	var err error
	cmk := &cmk{}
	cmk.PublicKey, err = a.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	// cmk.KeyMetadata = keyMetadata{
	// 	SigningAlgorithms: []string{signingAlgorithmSpecECDSA_SHA_256},
	// }
	return cmk, nil
}

func (a *aliClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	cmk, err := a.getCMK(ctx)
	if err != nil {
		return 0, err
	}
	return cmk.HashFunc(), nil
}

func (a *aliClient) getCMK(ctx context.Context) (*cmk, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, cmk](
		func(c *ttlcache.Cache[string, cmk], key string) *ttlcache.Item[string, cmk] {
			var k *cmk
			k, lerr = a.fetchCMK(ctx)
			if lerr == nil {
				return c.Set(cacheKey, *k, time.Second*300)
			}
			return nil
		},
	)

	item := a.keyCache.Get(cacheKey, ttlcache.WithLoader[string, cmk](loader))
	if lerr == nil {
		cmk := item.Value()
		return &cmk, nil
	}
	return nil, lerr
}

func (a *aliClient) createKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	// look for existing key first
	cmk, err := a.getCMK(ctx)
	if err == nil {
		out := cmk.PublicKey
		return out, nil
	}
	return nil, err
	//
	// // return error if not *kms.NotFoundException
	// var errNotFound *types.NotFoundException
	// if !errors.As(err, &errNotFound) {
	// 	return nil, fmt.Errorf("looking up key: %w", err)
	// }
	//
	// usage := types.KeyUsageTypeSignVerify
	// description := "Created by Sigstore"
	// key, err := a.client.CreateKey(ctx, &kms.CreateKeyInput{
	// 	CustomerMasterKeySpec: types.CustomerMasterKeySpec(algorithm),
	// 	KeyUsage:              usage,
	// 	Description:           &description,
	// })
	// if err != nil {
	// 	return nil, fmt.Errorf("creating key: %w", err)
	// }
	//
	// cmk, err = a.getCMK(ctx)
	// if err != nil {
	// 	return nil, fmt.Errorf("retrieving PublicKey from cache: %w", err)
	// }
	//
	// return cmk.PublicKey, err
}

func (a *aliClient) verify(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	cmk, err := a.getCMK(ctx)
	if err != nil {
		return err
	}
	verifier, err := cmk.Verifier()
	if err != nil {
		return err
	}
	return verifier.VerifySignature(sig, message, opts...)
}

func (a *aliClient) verifyRemotely(ctx context.Context, sig, digest []byte) error {
	alg := signingAlgorithmSpecECDSA_SHA_256
	messageType := "DIGEST"
	runtimeOpts := a.getRuntimeOpts()

	_, err := a.dkmsClient.VerifyWithOptions(&sdk.VerifyRequest{
		KeyId:       tea.String(a.keyId),
		Signature:   sig,
		Algorithm:   tea.String(alg),
		Message:     digest,
		MessageType: tea.String(messageType),
	}, runtimeOpts)

	if err != nil {
		return fmt.Errorf("unable to verify signature: %w", err)
	}
	return nil
}

func (a *aliClient) sign(ctx context.Context, digest []byte, _ crypto.Hash) ([]byte, error) {
	alg := signingAlgorithmSpecECDSA_SHA_256
	messageType := "DIGEST"
	runtimeOpts := a.getRuntimeOpts()

	out, err := a.dkmsClient.SignWithOptions(&sdk.SignRequest{
		KeyId:       tea.String(a.keyId),
		Algorithm:   tea.String(alg),
		Message:     digest,
		MessageType: tea.String(messageType),
	}, runtimeOpts)

	if err != nil {
		return nil, fmt.Errorf("signing with kms: %w", err)
	}
	return out.Signature, nil
}

func (a *aliClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	runtimeOpts := a.getRuntimeOpts()

	out, err := a.dkmsClient.GetPublicKeyWithOptions(&sdk.GetPublicKeyRequest{
		KeyId: tea.String(a.keyId),
	}, runtimeOpts)
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey([]byte(tea.StringValue(out.PublicKey)))
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return key, nil
}

func (a *aliClient) getRuntimeOpts() *openapiutil.RuntimeOptions {
	runtimeOpts := &openapiutil.RuntimeOptions{}
	if a.caCert == "" {
		runtimeOpts.IgnoreSSL = tea.Bool(true)
	} else {
		runtimeOpts.Verify = tea.String(a.caCert)
	}
	return runtimeOpts
}
