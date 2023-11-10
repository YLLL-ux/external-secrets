package tencent

import (
	"context"
	"fmt"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssm/v20190923"

	"github.com/external-secrets/external-secrets/pkg/utils"
)

type secretsManagerClient struct {
	config *common.Credential
	client *ssm.Client
	region string
}

type SecretsManagerClient interface {
	GetSecretValue(ctx context.Context, request *ssm.GetSecretValueRequest) (*ssm.GetSecretValueResponseParams, error)
}

var _ SecretsManagerClient = (*secretsManagerClient)(nil)

func newClient(credential common.CredentialIface, region string, clientProfile *profile.ClientProfile) (*secretsManagerClient, error) {
	ssmClient, err := ssm.NewClient(credential, region, clientProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %s", err)
	}

	return &secretsManagerClient{
		config: &common.Credential{
			SecretId:  credential.GetSecretId(),
			SecretKey: credential.GetSecretKey(),
		},
		client: ssmClient,
		region: region,
	}, nil
}

func (s *secretsManagerClient) GetSecretValue(ctx context.Context, request *ssm.GetSecretValueRequest) (*ssm.GetSecretValueResponseParams, error) {
	resp, err := s.client.GetSecretValue(request)
	if err != nil {
		return nil, fmt.Errorf("error getting secret [%s] latest value: %w", utils.Deref(request.SecretName), err)
	}

	fmt.Printf("GetSecretValue response: %v\n", resp)

	body, err := utils.ConvertToType[ssm.GetSecretValueResponseParams](resp)
	if err != nil {
		return nil, fmt.Errorf("error converting body: %w", err)
	}

	fmt.Printf("GetSecretValue body: %v\n", body)

	return &body, nil
}
