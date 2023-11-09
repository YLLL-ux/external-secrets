package util

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/client/config"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
)

const (
	errNilStore                                          = "found nil store"
	errMissingStoreSpec                                  = "store is missing spec"
	errMissingProvider                                   = "storeSpec is missing provider"
	errInvalidProvider                                   = "invalid provider spec. Missing Tencent field in store %s"
	errMissingAccessKeyID                                = "missing AccessKeyID"
	errInvalidClusterStoreMissingAccessKeyIDNamespace    = "invalid ClusterStore, missing  AccessKeyID namespace"
	errInvalidClusterStoreMissingServiceAccountNamespace = "invalid ServiceAccount, missing ca namespace"
	errFetchAccessKeyIDSecret                            = "could not fetch AccessKeyID secret: %s"
	errInvalidClusterStoreMissingSKNamespace             = "invalid ClusterStore, missing namespace"
	errMissingAccessKey                                  = "missing AccessSecretKey"
	errCredential                                        = "create credential failed"
	errInitRoleArnProvider                               = "failed to init RoleArn provider"
)

const (
	defaultDurationSeconds = 7200
	defaultAudience        = "sts.cloud.tencent.com"
	defaultSessionName     = "tencentcloud-go-sdk-"

	providerId         = "tke.cloud.tencent.com/providerID"
	roleARNAnnotation  = "tke.cloud.tencent.com/role-arn"
	audienceAnnotation = "tke.cloud.tencent.com/audience"
)

func GetProvider(store esv1beta1.GenericStore) (*esv1beta1.TencentProvider, error) {
	if store == nil {
		return nil, fmt.Errorf(errNilStore)
	}
	spc := store.GetSpec()
	if spc == nil {
		return nil, fmt.Errorf(errMissingStoreSpec)
	}
	if spc.Provider == nil {
		return nil, fmt.Errorf(errMissingProvider)
	}
	prov := spc.Provider.Tencent
	if prov == nil {
		return nil, fmt.Errorf(errInvalidProvider, store.GetObjectMeta().String())
	}
	return prov, nil
}

func NewAccessKeyAuth(ctx context.Context, kube kclient.Client, store esv1beta1.GenericStore, namespace string) (common.CredentialIface, error) {
	storeKind := store.GetObjectKind().GroupVersionKind().Kind
	tencentSpec, err := GetProvider(store)
	if err != nil {
		return nil, err
	}

	credentialsSecretName := tencentSpec.Auth.SecretRef.AccessKeyID.Name
	if credentialsSecretName == "" {
		return nil, fmt.Errorf(errMissingAccessKeyID)
	}

	objectKey := types.NamespacedName{
		Name:      credentialsSecretName,
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
	err = kube.Get(ctx, objectKey, credentialsSecret)
	if err != nil {
		return nil, fmt.Errorf(errFetchAccessKeyIDSecret, err)
	}

	objectKey = types.NamespacedName{
		Name:      tencentSpec.Auth.SecretRef.AccessKeySecret.Name,
		Namespace: namespace,
	}

	if storeKind == esv1beta1.ClusterSecretStoreKind {
		if tencentSpec.Auth.SecretRef.AccessKeySecret.Namespace == nil {
			return nil, fmt.Errorf(errInvalidClusterStoreMissingSKNamespace)
		}
		objectKey.Namespace = *tencentSpec.Auth.SecretRef.AccessKeySecret.Namespace
	}

	accessKeyID := credentialsSecret.Data[tencentSpec.Auth.SecretRef.AccessKeyID.Key]
	if (accessKeyID == nil) || (len(accessKeyID) == 0) {
		return nil, fmt.Errorf(errMissingAccessKeyID)
	}

	accessKeySecret := credentialsSecret.Data[tencentSpec.Auth.SecretRef.AccessKeySecret.Key]
	if (accessKeySecret == nil) || (len(accessKeySecret) == 0) {
		return nil, fmt.Errorf(errMissingAccessKey)
	}

	if tencentSpec.Role != "" {
		rap := common.DefaultRoleArnProvider(string(accessKeyID), string(accessKeySecret), tencentSpec.Role)
		if rap == nil {
			return nil, fmt.Errorf(errInitRoleArnProvider)
		}
		credential, err := rap.GetCredential()
		if err != nil {
			return nil, fmt.Errorf("invalid cred for roleArn provider: %s", err)
		}
		return credential, nil
	}

	credConfig := &common.Credential{
		SecretId:  string(accessKeyID),
		SecretKey: string(accessKeySecret),
	}

	return newCredential(store, credConfig)
}

func newCredential(store esv1beta1.GenericStore, config *common.Credential) (common.CredentialIface, error) {
	tencentSpec, err := GetProvider(store)
	if err != nil {
		return nil, err
	}

	if tencentSpec.Auth.SecretRef != nil {
		credential := common.NewCredential(config.SecretId, config.SecretKey)
		if credential == nil {
			return nil, fmt.Errorf(errCredential)
		}
		return credential, nil
	}

	return nil, fmt.Errorf(errInvalidProvider, store.GetObjectMeta().String())
}

func NewOIDCAuth(ctx context.Context, kube kclient.Client, store esv1beta1.GenericStore, namespace string) (common.CredentialIface, error) {
	tencentSpec, err := GetProvider(store)
	if err != nil {
		return nil, err
	}

	storeKind := store.GetObjectKind().GroupVersionKind().Kind
	name := tencentSpec.Auth.ServiceAccountRef.Name
	objectKey := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	if storeKind == esv1beta1.ClusterSecretStoreKind {
		if tencentSpec.Auth.ServiceAccountRef.Namespace == nil {
			return nil, fmt.Errorf(errInvalidClusterStoreMissingServiceAccountNamespace)
		}
		objectKey.Namespace = *tencentSpec.Auth.ServiceAccountRef.Namespace
	}

	sa := corev1.ServiceAccount{}
	err = kube.Get(ctx, objectKey, &sa)
	if err != nil {
		return nil, fmt.Errorf("get ServiceAccount failed: %s", err)
	}

	provID, ok := sa.Annotations[providerId]
	if !ok {
		return nil, fmt.Errorf("missing providerID in ServiceAccount annotation")
	}

	audience, ok := sa.Annotations[audienceAnnotation]
	if !ok {
		return nil, fmt.Errorf("missing audience in ServiceAccount annotation")
	}
	aud := []string{audience}
	cfg, err := ctrlcfg.GetConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	tokenFetcher := &authTokenFetcher{
		Namespace:      namespace,
		Audiences:      aud,
		ServiceAccount: name,
		k8sClient:      clientset.CoreV1(),
	}
	token, err := tokenFetcher.FetchToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch token failed: %s", err)
	}
	roleArn, ok := sa.Annotations[roleARNAnnotation]
	if !ok {
		return nil, fmt.Errorf("missing roleArn in ServiceAccount annotation")
	}
	sessionName := defaultSessionName + strconv.FormatInt(time.Now().UnixNano()/1000, 10)

	oap := common.NewOIDCRoleArnProvider(tencentSpec.RegionID, provID, string(token), roleArn, sessionName, defaultDurationSeconds)
	credential, err := oap.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("invalid cred for OIDC provider: %s", err)
	}
	return credential, nil
}
