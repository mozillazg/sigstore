// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"crypto"
	"encoding/gob"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"github.com/sigstore/sigstore/pkg/signature/kms/kmsgoplugin/common"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func init() {
	gob.Register(CryptoSigner{})
	gob.Register(CryptoSignerWrapper{})
}

type SignerVerifier struct {
	*fake.SignerVerifier
}

func (g SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	signer := CryptoSigner{
		SignerVerifier: &g,
	}
	opts := common.GetHashFuncFromEnv()
	return signer, opts, nil
}

type CryptoSigner struct {
	crypto.Signer
	*SignerVerifier
}

func (c CryptoSigner) Public() crypto.PublicKey {
	publicKey, err := c.PublicKey()
	if err != nil {
		panic(err)
	}
	return publicKey
}

func (c CryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	emptyMessage := strings.NewReader("")
	hashFunc := common.GetHashFuncFromEnv()
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	signOpts := []signature.SignOption{
		options.WithContext(context.Background()),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}
	return c.SignMessage(emptyMessage, signOpts...)
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Info,
		Output:     os.Stderr,
		JSONFormat: true,
	})

	fakeSV, err := fake.LoadSignerVerifier(context.TODO(), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	wrappedSignerVerifier := SignerVerifier{
		SignerVerifier: fakeSV,
	}

	// wrappedSignerVerifier := LocalSignerVerifier{}

	// You can use the KeyResourceID
	logger.Info(
		"env",
		common.KeyResourceIDEnvKey, common.GetKeyResourceIDFromEnv(),
	)

	common.ServePlugin(wrappedSignerVerifier, logger)
}
