/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package secretstore

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esapi "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore/metrics"
)

const (
	errStoreProvider       = "could not get store provider: %w"
	errStoreClient         = "could not get provider client: %w"
	errValidationFailed    = "could not validate provider: %w"
	errPatchStatus         = "unable to patch status: %w"
	errUnableCreateClient  = "unable to create client"
	errUnableValidateStore = "unable to validate store"
	errUnableGetProvider   = "unable to get store provider"

	msgStoreValidated = "store validated"
)

// ss与css使用相同的reconcile函数
// 1.如果调谐完成则直接返回
// 2.更新刷新时间
// 3.验证ss（验证是否SecretsClient以及provider）
// 4.设置status、记录event、设置Condition
// 5.使用SecretsClient去patch status
func reconcile(ctx context.Context, req ctrl.Request, ss esapi.GenericStore, cl client.Client, log logr.Logger,
	controllerClass string, gaugeVecGetter metrics.GaugeVevGetter, recorder record.EventRecorder, requeueInterval time.Duration) (ctrl.Result, error) {
	if !ShouldProcessStore(ss, controllerClass) {
		log.V(1).Info("skip store")
		return ctrl.Result{}, nil
	}

	// 更新ss的刷新间隔
	if ss.GetSpec().RefreshInterval != 0 {
		requeueInterval = time.Second * time.Duration(ss.GetSpec().RefreshInterval)
	}

	// patch status when done processing
	p := client.MergeFrom(ss.Copy())
	defer func() {
		err := cl.Status().Patch(ctx, ss, p) // 更新ss的Status
		if err != nil {
			log.Error(err, errPatchStatus)
		}
	}()

	// validateStore modifies the store conditions
	// we have to patch the status
	log.V(1).Info("validating")
	err := validateStore(ctx, req.Namespace, controllerClass, ss, cl, gaugeVecGetter, recorder)
	if err != nil {
		log.Error(err, "unable to validate store")
		return ctrl.Result{}, err
	}
	storeProvider, err := esapi.GetProvider(ss)
	if err != nil {
		return ctrl.Result{}, err
	}
	// 设置ss的Status
	capStatus := esapi.SecretStoreStatus{
		Capabilities: storeProvider.Capabilities(),
		Conditions:   ss.GetStatus().Conditions,
	}
	ss.SetStatus(capStatus)

	// 记录ss的event，controller会发送apiserver
	recorder.Event(ss, v1.EventTypeNormal, esapi.ReasonStoreValid, msgStoreValidated)
	// 更新ss的Condition
	cond := NewSecretStoreCondition(esapi.SecretStoreReady, v1.ConditionTrue, esapi.ReasonStoreValid, msgStoreValidated)
	SetExternalSecretCondition(ss, *cond, gaugeVecGetter)

	return ctrl.Result{
		RequeueAfter: requeueInterval,
	}, err
}

// validateStore tries to construct a new client
// if it fails sets a condition and writes events.
func validateStore(ctx context.Context, namespace, controllerClass string, store esapi.GenericStore,
	client client.Client, gaugeVecGetter metrics.GaugeVevGetter, recorder record.EventRecorder) error {
	mgr := NewManager(client, controllerClass, false)
	defer mgr.Close(ctx)
	cl, err := mgr.GetFromStore(ctx, store, namespace) // 获取SecretsClient
	if err != nil {
		// 构建SecretStore的Condition
		// 条件类型：SecretStoreReady	状态：ConditionFalse
		// 原因：ReasonInvalidProviderConfig	错误变量：errUnableCreateClient
		cond := NewSecretStoreCondition(esapi.SecretStoreReady, v1.ConditionFalse, esapi.ReasonInvalidProviderConfig, errUnableCreateClient)
		// 为SecretStore设置Condition
		SetExternalSecretCondition(store, *cond, gaugeVecGetter)
		// 这是 controller-runtime 包中用于记录 Kubernetes 事件的函数。它允许控制器向 Kubernetes API 报告事件。
		recorder.Event(store, v1.EventTypeWarning, esapi.ReasonInvalidProviderConfig, err.Error()) // recorder是secret-store
		return fmt.Errorf(errStoreClient, err)
	}
	validationResult, err := cl.Validate() // 调用provider的Validate实现方法验证provider是否ok
	if err != nil && validationResult != esapi.ValidationResultUnknown {
		cond := NewSecretStoreCondition(esapi.SecretStoreReady, v1.ConditionFalse, esapi.ReasonValidationFailed, errUnableValidateStore)
		SetExternalSecretCondition(store, *cond, gaugeVecGetter)
		recorder.Event(store, v1.EventTypeWarning, esapi.ReasonValidationFailed, err.Error())
		return fmt.Errorf(errValidationFailed, err)
	}

	return nil
}

// ShouldProcessStore returns true if the store should be processed.
func ShouldProcessStore(store esapi.GenericStore, class string) bool {
	if store == nil || store.GetSpec().Controller == "" || store.GetSpec().Controller == class {
		return true
	}

	return false
}
