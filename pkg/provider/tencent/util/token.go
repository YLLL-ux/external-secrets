package util

import (
	"context"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("provider").WithName("tencent")

type authTokenFetcher struct {
	Namespace      string
	Audiences      []string
	ServiceAccount string
	k8sClient      corev1.CoreV1Interface
}

func (p authTokenFetcher) FetchToken(ctx context.Context) ([]byte, error) {
	log.V(1).Info("fetching token", "ns", p.Namespace, "sa", p.ServiceAccount)
	tokRsp, err := p.k8sClient.ServiceAccounts(p.Namespace).CreateToken(ctx, p.ServiceAccount, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences: p.Audiences,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("error creating service account token: %w", err)
	}
	return []byte(tokRsp.Status.Token), nil
}
