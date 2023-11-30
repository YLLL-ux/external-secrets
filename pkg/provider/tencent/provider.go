package tencent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssm/v20190923"
	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/provider/tencent/util"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

var _ esv1beta1.Provider = &SecretsManager{}
var _ esv1beta1.SecretsClient = &SecretsManager{}

type SecretsManager struct {
	Client SSMInterface
}

type SSMInterface interface {
	GetSecretValue(ctx context.Context, request *ssm.GetSecretValueRequest) (*ssm.GetSecretValueResponseParams, error)
}

const (
	errInitTencentProvider          = "unable to initialize tencent provider: %s"
	errTencentClient                = "cannot setup new Tencent client: %w"
	errUninitializedTencentProvider = "provider Tencent is not initialized"
)

func (s *SecretsManager) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube kclient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	var esoCred common.CredentialIface
	tencentSpec, err := util.GetProvider(store)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf(errInitTencentProvider, "nil store")
	}

	// case: use SecretRef
	if tencentSpec.Auth.SecretRef != nil {
		cred, err := util.NewAccessKeyAuth(ctx, kube, store, namespace)
		if err != nil {
			return nil, err
		}
		esoCred = cred
	}

	// case: use OIDC
	if tencentSpec.Auth.ServiceAccountRef != nil {
		cred, err := util.NewOIDCAuth(ctx, kube, store, namespace)
		if err != nil {
			return nil, err
		}
		esoCred = cred
	}

	region := tencentSpec.RegionID
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssm.tencentcloudapi.com"

	client, err := newClient(esoCred, region, cpf)
	if err != nil {
		return nil, fmt.Errorf(errTencentClient, err)
	}

	s.Client = client

	return s, nil
}

func (s *SecretsManager) ValidateStore(store esv1beta1.GenericStore) error {
	tencentSpec, err := util.GetProvider(store)
	if err != nil {
		return err
	}
	regionID := tencentSpec.RegionID
	if regionID == "" {
		return fmt.Errorf("missing tencent region")
	}

	switch {
	case tencentSpec.Auth.SecretRef != nil:
		return s.validateStoreAccessKeyAuth(store)
	case tencentSpec.Auth.ServiceAccountRef != nil:
		return s.validateStoreOIDCAuth(store)
	default:
		return fmt.Errorf("missing tencent auth provider")
	}
}

func (s *SecretsManager) validateStoreAccessKeyAuth(store esv1beta1.GenericStore) error {
	tencentSpec, err := util.GetProvider(store)
	if err != nil {
		return err
	}

	accessKeyID := tencentSpec.Auth.SecretRef.AccessKeyID
	err = utils.ValidateSecretSelector(store, accessKeyID)
	if err != nil {
		return err
	}
	if accessKeyID.Name == "" {
		return fmt.Errorf("missing tencent access ID name")
	}
	if accessKeyID.Key == "" {
		return fmt.Errorf("missing tencent access ID key")
	}

	accessKeySecret := tencentSpec.Auth.SecretRef.AccessKeySecret
	err = utils.ValidateSecretSelector(store, accessKeySecret)
	if err != nil {
		return err
	}
	if accessKeySecret.Name == "" {
		return fmt.Errorf("missing tencent access key secret name")
	}
	if accessKeySecret.Key == "" {
		return fmt.Errorf("missing tencent access key secret key")
	}

	return nil
}

func (s *SecretsManager) validateStoreOIDCAuth(store esv1beta1.GenericStore) error {
	tencentSpec, err := util.GetProvider(store)
	if err != nil {
		return err
	}

	if tencentSpec.Auth.SecretRef != nil && tencentSpec.Auth.ServiceAccountRef != nil {
		return fmt.Errorf("cannot use SecretRef and ServiceAccountName at the same time")
	}

	if tencentSpec.Auth.ServiceAccountRef != nil && tencentSpec.Role != "" {
		return fmt.Errorf("cannot set role and ServiceAccountName at the same time")
	}

	if tencentSpec.Auth.ServiceAccountRef != nil {
		return nil
	}

	return fmt.Errorf("tencentRef is not tencentAuth")
}

// Capabilities returns the provider Capabilities (Read, Write, ReadWrite)
func (s *SecretsManager) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

// GetSecret returns a single secret from the provider.
func (s *SecretsManager) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	if utils.IsNil(s.Client) {
		return nil, fmt.Errorf(errUninitializedTencentProvider)
	}

	request := ssm.NewGetSecretValueRequest()
	request.SecretName = &ref.Key
	if ref.Version != "" {
		request.VersionId = &ref.Version
	}

	secretOut, err := s.Client.GetSecretValue(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret value: %w", err)
	}

	if ref.Property == "" {
		if utils.Deref(secretOut.SecretString) != "" {
			return []byte(utils.Deref(secretOut.SecretString)), nil
		}
		return nil, fmt.Errorf("invalid secret received. no secret string nor binary for key: %s", ref.Key)
	}

	var payload string
	if utils.Deref(secretOut.SecretString) != "" {
		payload = utils.Deref(secretOut.SecretString)
	}
	val := gjson.Get(payload, ref.Property)
	if !val.Exists() {
		return nil, fmt.Errorf("key %s does not exist in secret %s", ref.Property, ref.Key)
	}
	return []byte(val.String()), nil
}

// GetSecretMap returns multiple k/v pairs from the provider.
func (s *SecretsManager) GetSecretMap(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	data, err := s.GetSecret(ctx, ref)
	if err != nil {
		return nil, err
	}

	kv := make(map[string]string)
	err = json.Unmarshal(data, &kv)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal secret %s: %w", ref.Key, err)
	}

	secretData := make(map[string][]byte)
	for k, v := range kv {
		secretData[k] = []byte(v)
	}
	return secretData, nil
}

func (s *SecretsManager) GetAllSecrets(_ context.Context, _ esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, fmt.Errorf("GetAllSecrets not implemented")
}

func (s *SecretsManager) PushSecret(_ context.Context, _ []byte, _ corev1.SecretType, _ *apiextensionsv1.JSON, _ esv1beta1.PushRemoteRef) error {
	return fmt.Errorf("not implemented")
}

func (s *SecretsManager) DeleteSecret(_ context.Context, _ esv1beta1.PushRemoteRef) error {
	return fmt.Errorf("not implemented")
}

func (s *SecretsManager) Validate() (esv1beta1.ValidationResult, error) {
	return esv1beta1.ValidationResultReady, nil
}

func (s *SecretsManager) Close(_ context.Context) error {
	return nil
}

func init() {
	esv1beta1.Register(&SecretsManager{}, &esv1beta1.SecretStoreProvider{
		Tencent: &esv1beta1.TencentProvider{},
	})
}
