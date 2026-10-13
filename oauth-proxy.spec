# /!\ This file is maintained at https://github.com/openshift/oauth-proxy
%global debug_package   %{nil}
%global snapshot	1

%if ! 0%{?gobuild:1}
%define gobuild(o:) go build -ldflags "${LDFLAGS:-} -B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \\n')" -a -v -x %{?**};
%endif

%global provider        github
%global provider_tld    com
%global project         openshift
%global repo            oauth-proxy
# https://github.com/openshift/oauth-proxy
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
# %commit is intended to be set by tito. The values in this spec file will not be kept up to date.
%{!?commit:
%global commit          57b6863264c89307830fccadf2f122e5cea3d2a0
}
%global shortcommit     %(c=%{commit}; echo ${c:0:7})
%global gopathdir       %{_sourcedir}/go
%global upstream_ver    2.3
%global rpm_ver         %(v=%{upstream_ver}; echo ${v//-/_})
%global download_prefix %{provider}.%{provider_tld}/openshift/%{repo}

Name:   golang-%{provider}-%{project}-%{repo}
# Version and release information will be automatically managed by CD
# It will be kept in sync with OCP builds.
Version:  %{rpm_ver}
Release:  1.git%{shortcommit}%{?dist}
Summary:	A reverse proxy that provides authentication with OpenShift and other OAuth providers
License:	MIT
URL:		  https://%{provider}.%{provider_tld}/%{project}/%{repo}
Source0:  https://%{download_prefix}/archive/%{commit}/%{repo}-%{commit}.tar.gz

# e.g. el6 has ppc64 arch without gcc-go, so EA tag is required
ExclusiveArch:  %{?go_arches:%{go_arches}}%{!?go_arches:%{ix86} x86_64 aarch64 %{arm} ppc64le s390x}
# If go_compiler is not set to 1, there is no virtual provide. Use golang instead.
BuildRequires: %{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}

Provides:      %{repo} = %{version}-%{release}

%description
%{summary}

%prep
%setup -q -n %{repo}-%{commit}

%build
# Go expects a full path to the sources which is not included in the source
# tarball so create a link with the expected path
mkdir -p %{gopathdir}/src/%{provider}.%{provider_tld}/%{project}
GOSRCDIR=%{gopathdir}/src/%{import_path}
if [ ! -e "$GOSRCDIR" ]; then
  ln -s `pwd` "$GOSRCDIR"
fi
export GOPATH=%{gopathdir}

# Ensure the default GOBIN is used ${GOPATH}/bin
# unset GOBIN // needed?
export LDFLAGS='-s -w'
%gobuild %{import_path}

%install
install -d %{buildroot}%{_bindir}
install -D -p -m 0755 %{repo} %{buildroot}/%{_bindir}/%{repo}

%files
%license LICENSE
%{_bindir}/%{repo}

%changelog
* Thu Apr 12 2018 Simo Sorce <simo@redhat.com> - 2.3-1.git57b68632
- New release
