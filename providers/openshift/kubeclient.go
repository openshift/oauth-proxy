package openshift

import (
	"flag"

	"k8s.io/client-go/kubernetes"
)

type KubeClientOptions struct {
	// RemoteKubeConfigFile is the file to use to connect to a "normal" kube API server
	RemoteKubeConfigFile string
}

func NewKubeClientOptions() *KubeClientOptions {
	return &KubeClientOptions{}
}

func (o *KubeClientOptions) Validate() []error {
	return []error{}
}

func (o *KubeClientOptions) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.RemoteKubeConfigFile, "kubeconfig", o.RemoteKubeConfigFile, ""+
		"kubeconfig file pointing at the 'core' OpenShift server that has the oauth-server running on it")
}

func (o *KubeClientOptions) ToKubeClientConfig() (*kubernetes.Clientset, error) {
	clientConfig, err := GetClientConfig(o.RemoteKubeConfigFile)
	if err != nil {
		return nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	return kubeClient, nil
}
