module github.com/sigstore/sigstore/cmd/sigstore-kms-alibabakms

go 1.23.0

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/sigstore/sigstore v1.8.10
	github.com/sigstore/sigstore/pkg/signature/kms/alibaba v0.0.0-00010101000000-000000000000
	github.com/sigstore/sigstore/pkg/signature/kms/cliplugin v0.0.0-00010101000000-000000000000
)

replace (
	github.com/sigstore/sigstore => ../../
	github.com/sigstore/sigstore/pkg/signature/kms/alibaba => ../../pkg/signature/kms/alibaba
	github.com/sigstore/sigstore/pkg/signature/kms/cliplugin => ../../pkg/signature/kms/cliplugin
)

require (
	github.com/AliyunContainerService/ack-ram-tool/pkg/credentials/provider v0.15.1 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-pop v0.0.6 // indirect
	github.com/alibabacloud-go/alibabacloud-gateway-spi v0.0.4 // indirect
	github.com/alibabacloud-go/darabonba-array v0.1.0 // indirect
	github.com/alibabacloud-go/darabonba-encode-util v0.0.2 // indirect
	github.com/alibabacloud-go/darabonba-map v0.0.2 // indirect
	github.com/alibabacloud-go/darabonba-openapi/v2 v2.0.9 // indirect
	github.com/alibabacloud-go/darabonba-signature-util v0.0.7 // indirect
	github.com/alibabacloud-go/darabonba-string v1.0.2 // indirect
	github.com/alibabacloud-go/debug v1.0.0 // indirect
	github.com/alibabacloud-go/endpoint-util v1.1.0 // indirect
	github.com/alibabacloud-go/kms-20160120/v3 v3.2.3 // indirect
	github.com/alibabacloud-go/openapi-util v0.1.0 // indirect
	github.com/alibabacloud-go/tea v1.2.2 // indirect
	github.com/alibabacloud-go/tea-utils v1.4.4 // indirect
	github.com/alibabacloud-go/tea-utils/v2 v2.0.6 // indirect
	github.com/alibabacloud-go/tea-xml v1.1.3 // indirect
	github.com/aliyun/credentials-go v1.3.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clbanning/mxj/v2 v2.5.5 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/google/go-containerregistry v0.20.2 // indirect
	github.com/jellydator/ttlcache/v3 v3.3.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/letsencrypt/boulder v0.0.0-20240620165639-de9c06129bec // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/term v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
