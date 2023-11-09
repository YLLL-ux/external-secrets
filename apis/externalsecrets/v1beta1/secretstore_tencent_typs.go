package v1beta1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

type TencentAuth struct {
	SecretRef *TencentAuthSecretRef `json:"secretRef,omitempty"`
}

// TencentSecretRef holds secret references for Tencent credentials.
type TencentAuthSecretRef struct {
	// The AccessKeyID is used for authentication
	AccessKeyID esmeta.SecretKeySelector `json:"accessKeyIDSecretRef"`
	// The AccessKeySecret is used for authentication
	AccessKeySecret esmeta.SecretKeySelector `json:"accessKeySecretSecretRef"`
}

// TencentProvider configures a store to sync secrets using the Tencent Secrets Manager.
type TencentProvider struct {
	Auth TencentAuth `json:"auth"`
	// Tencent  Region to be used for the provider
	RegionID string `json:"regionID"`
}
