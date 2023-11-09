package v1beta1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

type TencentAuth struct {
	SecretRef *TencentSecretRef `json:"secretRef,omitempty"`
}

// TencentSecretRef holds secret references for Tencent credentials.
type TencentSecretRef struct {
	// The AccessKeyID is used for authentication
	AccessKeyID esmeta.SecretKeySelector `json:"accessKeyIDSecretRef,omitempty"`
	// The AccessKeySecret is used for authentication
	AccessKeySecret esmeta.SecretKeySelector `json:"accessKeySecretSecretRef"`
}

// TencentProvider configures a store to sync secrets using the Tencent Secrets Manager.
type TencentProvider struct {
	Auth TencentAuth `json:"auth,omitempty"`
	// Tencent  Region to be used for the provider
	RegionID string `json:"regionID"`
}
