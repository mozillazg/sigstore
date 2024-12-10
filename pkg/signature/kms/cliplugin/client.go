package cliplugin

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/common"
)

const (
	ReferenceScheme = "sigstore-kms-"
)

func init() {
	kms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (kms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, hashFunc)
	})
}

func LoadSignerVerifier(ctx context.Context, inputKeyresourceID string, hashFunc crypto.Hash) (sigkms.SignerVerifier, error) {
	parts := strings.SplitN(inputKeyresourceID, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: expected format: [binary name]://[key ref], got: %s", ErrorParsingPluginBinaryName, inputKeyresourceID)
	}
	executable, keyResourceID := parts[0], parts[1]
	initOptions := &common.InitOptions{
		ProtocolVersion: common.ProtocolVersion,
		KeyResourceID:   keyResourceID,
		HashFunc:        hashFunc,
	}
	if ctxDeadline, ok := ctx.Deadline(); ok {
		initOptions.CtxDeadline = &ctxDeadline
	}
	pluginClient := newPluginClient(executable, initOptions, makeCommand)
	return pluginClient, nil
}
