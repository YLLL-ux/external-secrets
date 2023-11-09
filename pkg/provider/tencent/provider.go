package tencent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/avast/retry-go/v4"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssm/v20190923"
	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/provider/tencent/util"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

const (
	errTencentCredSecretName                          = "invalid Tencent SecretStore resource: missing Tencent APIKey"
	errInvalidClusterStoreMissingAccessKeyIDNamespace = "invalid ClusterStore, missing  AccessKeyID namespace"
	errFetchAccessKeyIDSecret                         = "could not fetch AccessKeyID secret: %w"
	errInvalidClusterStoreMissingSKNamespace          = "invalid ClusterStore, missing namespace"
	errMissingAccessKeyID                             = "missing AccessKeyID"
	errMissingAccessKey                               = "missing AccessSecretKey"
	errTencentClient                                  = "cannot setup new Tencent client: %w"
	errCredential                                     = "create credential failed"
	errUninitializedTencentProvider                   = "provider Tencent is not initialized"
	errMissingToken                                   = "missing token"
	errInitTencentProvider                            = "unable to initialize tencent provider: %s"
)

var _ esv1beta1.Provider = &SecretsManager{}
var _ esv1beta1.SecretsClient = &SecretsManager{}

type SecretsManager struct {
	Client SSMInterface
	Config *common.Credential
}

type SSMInterface interface {
	GetSecretValue(ctx context.Context, request *ssm.GetSecretValueRequest) (*ssm.GetSecretValueResponseParams, error)
}

// Capabilities return the provider supported capabilities (ReadOnly, WriteOnly, ReadWrite).
func (s *SecretsManager) Capabilities() esv1beta1.SecretStoreCapabilities {
	return esv1beta1.SecretStoreReadOnly
}

// NewClient constructs a new secrets client based on the provided store.
func (s *SecretsManager) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube kclient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	prov, err := util.GetProvider(store)
	if err != nil {
		return nil, err
	}

	if store == nil {
		return nil, fmt.Errorf(errInitTencentProvider, "nil store")
	}
	credential, err := newAuth(ctx, kube, store, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create Tencent credentials: %w", err)
	}

	region := prov.RegionID
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssm.tencentcloudapi.com"

	client, err := newClient(credential, region, cpf)
	if err != nil {
		return nil, fmt.Errorf(errTencentClient, err)
	}

	s.Client = client

	return s, nil
}

func newAuth(ctx context.Context, kube kclient.Client, store esv1beta1.GenericStore, namespace string) (common.CredentialIface, error) {
	storeSpec := store.GetSpec()
	tencentSpec := storeSpec.Provider.Tencent

	if tencentSpec.Auth.SecretRef != nil {
		credentials, err := newAccessKeyAuth(ctx, kube, store, namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to create Tencent AccessKey credentials: %w", err)
		}
		return credentials, nil
	}

	return nil, fmt.Errorf("tencent authentication methods wasn't provided")
}

func newAccessKeyAuth(ctx context.Context, kube kclient.Client, store esv1beta1.GenericStore, namespace string) (common.CredentialIface, error) {
	storeSpec := store.GetSpec()
	tencentSpec := storeSpec.Provider.Tencent
	storeKind := store.GetObjectKind().GroupVersionKind().Kind

	credentialsSecretNameForID := tencentSpec.Auth.SecretRef.AccessKeyID.Name
	if credentialsSecretNameForID == "" {
		return nil, fmt.Errorf(errTencentCredSecretName)
	}
	objectKey := types.NamespacedName{
		Name:      credentialsSecretNameForID,
		Namespace: namespace,
	}

	// only ClusterStore is allowed to set namespace (and then it's required)
	if storeKind == esv1beta1.ClusterSecretStoreKind {
		if tencentSpec.Auth.SecretRef.AccessKeyID.Namespace == nil {
			return nil, fmt.Errorf(errInvalidClusterStoreMissingAccessKeyIDNamespace)
		}
		objectKey.Namespace = *tencentSpec.Auth.SecretRef.AccessKeyID.Namespace
	}

	credentialsSecret := &corev1.Secret{}
	err := kube.Get(ctx, objectKey, credentialsSecret)
	if err != nil {
		return nil, fmt.Errorf(errFetchAccessKeyIDSecret, err)
	}

	credentialsSecretNameForSecret := tencentSpec.Auth.SecretRef.AccessKeySecret.Name
	if credentialsSecretNameForSecret == "" {
		return nil, fmt.Errorf(errTencentCredSecretName)
	}
	objectKey = types.NamespacedName{
		Name:      credentialsSecretNameForSecret,
		Namespace: namespace,
	}

	if storeKind == esv1beta1.ClusterSecretStoreKind {
		if tencentSpec.Auth.SecretRef.AccessKeySecret.Namespace == nil {
			return nil, fmt.Errorf(errInvalidClusterStoreMissingSKNamespace)
		}
		objectKey.Namespace = *tencentSpec.Auth.SecretRef.AccessKeySecret.Namespace
	}
	err = kube.Get(ctx, objectKey, credentialsSecret)
	if err != nil {
		return nil, fmt.Errorf(errFetchAccessKeyIDSecret, err)
	}

	accessKeyID := credentialsSecret.Data[tencentSpec.Auth.SecretRef.AccessKeyID.Key]
	if (accessKeyID == nil) || (len(accessKeyID) == 0) {
		return nil, fmt.Errorf(errMissingAccessKeyID)
	}

	accessKeySecret := credentialsSecret.Data[tencentSpec.Auth.SecretRef.AccessKeySecret.Key]
	if (accessKeySecret == nil) || (len(accessKeySecret) == 0) {
		return nil, fmt.Errorf(errMissingAccessKey)
	}

	return newCredential(utils.Ptr(string(accessKeyID)), utils.Ptr(string(accessKeySecret)))
}

// newCredential constructs a new credential based on the provided accessKeyID and accessKeySecret
func newCredential(accessKeyID, accessKeySecret *string) (common.CredentialIface, error) {
	SecretId := util.Ptr2String(accessKeyID)
	SecretKey := util.Ptr2String(accessKeySecret)

	credential := common.NewCredential(SecretId, SecretKey)
	if credential == nil {
		return nil, fmt.Errorf(errCredential)
	}
	return credential, nil
}

func (s *SecretsManager) Validate() (esv1beta1.ValidationResult, error) {
	err := retry.Do(
		func() error {
			token := s.Config.GetToken()
			if token == "" {
				return fmt.Errorf(errMissingToken)
			}

			return nil
		},
		retry.Attempts(5),
	)

	if err != nil {
		return esv1beta1.ValidationResultError, fmt.Errorf("failed to validate Tencent credentials: %w", err)
	}

	return esv1beta1.ValidationResultReady, nil
}

func (s *SecretsManager) ValidateStore(store esv1beta1.GenericStore) error {
	storeSpec := store.GetSpec()
	tencentSpec := storeSpec.Provider.Tencent

	regionID := tencentSpec.RegionID

	if regionID == "" {
		return fmt.Errorf("missing tencent region")
	}

	return s.validateStoreAuth(store)
}

func (s *SecretsManager) validateStoreAuth(store esv1beta1.GenericStore) error {
	storeSpec := store.GetSpec()
	tencentSpec := storeSpec.Provider.Tencent

	if tencentSpec.Auth.SecretRef != nil {
		return s.validateStoreAccessKeyAuth(store)
	}

	return fmt.Errorf("missing tencent auth provider")
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

func (s *SecretsManager) DeleteSecret(_ context.Context, _ esv1beta1.PushRemoteRef) error {
	return fmt.Errorf("not implemented")
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

func (kms *SecretsManager) Close(_ context.Context) error {
	return nil
}

func init() {
	esv1beta1.Register(&SecretsManager{}, &esv1beta1.SecretStoreProvider{
		Tencent: &esv1beta1.TencentProvider{},
	})
}
