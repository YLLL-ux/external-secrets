package tencent

import (
	"testing"

	pointer "k8s.io/utils/ptr"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

func TestValidateStore(t *testing.T) {
	ssm := SecretsManager{}

	accessSecret := &esv1beta1.SecretStore{
		Spec: esv1beta1.SecretStoreSpec{
			Provider: &esv1beta1.SecretStoreProvider{
				Tencent: &esv1beta1.TencentProvider{
					Role:     "qcs::cam::uin/700000611005:roleName/test-1",
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

	oidc := &esv1beta1.SecretStore{
		Spec: esv1beta1.SecretStoreSpec{
			Provider: &esv1beta1.SecretStoreProvider{
				Tencent: &esv1beta1.TencentProvider{
					RegionID: "region-1",
					Auth: esv1beta1.TencentAuth{
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name: "foobar",
						},
					},
				},
			},
		},
	}

	oidc2 := &esv1beta1.SecretStore{
		Spec: esv1beta1.SecretStoreSpec{
			Provider: &esv1beta1.SecretStoreProvider{
				Tencent: &esv1beta1.TencentProvider{
					RegionID: "region-1",
					Auth: esv1beta1.TencentAuth{
						ServiceAccountRef: &esmeta.ServiceAccountSelector{
							Name:      "foobar",
							Namespace: pointer.To("test"),
						},
					},
				},
			},
		},
	}

	err := ssm.ValidateStore(accessSecret)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = ssm.ValidateStore(oidc)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = ssm.ValidateStore(oidc2)
	if err != nil {
		t.Errorf(err.Error())
	}
}
