module github.com/openshift/oauth-proxy

go 1.15

require (
	github.com/18F/hmacauth v0.0.0-20151013130326-9232a6386b73
	github.com/BurntSushi/toml v0.3.1
	github.com/bitly/go-simplejson v0.5.1-0.20170206154632-da1a8928f709
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869
	github.com/fsnotify/fsnotify v1.4.9
	github.com/mreiferson/go-options v1.0.0
	github.com/openshift/api v0.0.0-20200827090112-c05698d102cf
	github.com/openshift/build-machinery-go v0.0.0-20200819073603-48aa266c95f7
	github.com/openshift/client-go v0.0.0-20200827190008-3062137373b5
	github.com/openshift/library-go v0.0.0-20200918101923-1e4c94603efe
	github.com/stretchr/testify v1.4.0
	github.com/yhat/wsutil v0.0.0-20170731153501-1d66fa95c997
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/apiserver v0.19.2
	k8s.io/client-go v0.19.2
)

replace (
	golang.org/x/net => golang.org/x/net v0.0.0-20210525063256-abc453219eb5 // CVE-2021-33194
	vbom.ml/util => github.com/fvbommel/util v0.0.0-20180919145318-efcd4e0f9787
)
