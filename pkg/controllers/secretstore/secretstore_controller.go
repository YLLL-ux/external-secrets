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
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	esapi "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	ctrlmetrics "github.com/external-secrets/external-secrets/pkg/controllers/metrics"
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore/ssmetrics"

	// Loading registered providers.
	_ "github.com/external-secrets/external-secrets/pkg/provider/register"
)

// StoreReconciler reconciles a SecretStore object.
type StoreReconciler struct {
	client.Client
	Log             logr.Logger
	Scheme          *runtime.Scheme
	recorder        record.EventRecorder // 事件记录器
	RequeueInterval time.Duration
	ControllerClass string
}

// Reconcile 对ss进行调谐处理
// 1.日志记录初始化
// 2.设置资源标签
// 3.记录开始时间
// 4.初始化度量指标
// 5.延迟函数记录度量指标
// 6.从缓存中读取ss
// 7.处理ss不存在的错误
// 8.处理其他错误
// 9.调用reconcile函数
func (r *StoreReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("secretstore", req.NamespacedName) // 将ss=req.NamespacedName绑定，有助于在日志中区分不同的ss实例

	resourceLabels := ctrlmetrics.RefineNonConditionMetricLabels(map[string]string{"name": req.Name, "namespace": req.Namespace})
	start := time.Now()

	secretStoreReconcileDuration := ssmetrics.GetGaugeVec(ssmetrics.SecretStoreReconcileDurationKey)
	defer func() { secretStoreReconcileDuration.With(resourceLabels).Set(float64(time.Since(start))) }()

	var ss esapi.SecretStore
	err := r.Get(ctx, req.NamespacedName, &ss) // 从缓存读取ss
	if apierrors.IsNotFound(err) {             // ss不存在
		ssmetrics.RemoveMetrics(req.Namespace, req.Name)
		return ctrl.Result{}, nil
	} else if err != nil { // 其他错误
		log.Error(err, "unable to get SecretStore")
		return ctrl.Result{}, err
	}

	return reconcile(ctx, req, &ss, r.Client, log, r.ControllerClass, ssmetrics.GetGaugeVec, r.recorder, r.RequeueInterval)
}

// SetupWithManager returns a new controller builder that will be started by the provided Manager.
// 1.设置事件记录器
// 2.注册控制器
func (r *StoreReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	// 设置事件记录器
	r.recorder = mgr.GetEventRecorderFor("secret-store") // 确保SecretStore资源的事件是与secret-store控制器相关

	// NewControllerManagedBy注册StoreReconciler
	return ctrl.NewControllerManagedBy(mgr). // 创建一个新的控制器，并将其管理权交给mgr
							WithOptions(opts).         // 设置控制器的选项
							For(&esapi.SecretStore{}). // 指定控制器监视的资源类型为SecretStore
							Complete(r)                // 完成控制器的设置，并将StoreReconciler实例r作为控制器的实现
}
