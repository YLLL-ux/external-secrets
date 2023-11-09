package tencent

import (
	"testing"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

func TestValidateAccessKeyStore(t *testing.T) {
	ssm := SecretsManager{}

	store := &esv1beta1.SecretStore{
		Spec: esv1beta1.SecretStoreSpec{
			Provider: &esv1beta1.SecretStoreProvider{
				Tencent: &esv1beta1.TencentProvider{
					RegionID: "region-1",
					Auth: esv1beta1.TencentAuth{
						SecretRef: &esv1beta1.TencentAuthSecretRef{
							AccessKeyID: esmeta.SecretKeySelector{
								Name: "accessKeyID",
								Key:  "key-1",
							},
							AccessKeySecret: esmeta.SecretKeySelector{
								Name: "accessKeySecret",
								Key:  "key-1",
							},
						},
					},
				},
			},
		},
	}

	err := ssm.ValidateStore(store)
	if err != nil {
		t.Errorf(err.Error())
	}
}
