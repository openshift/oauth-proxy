FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.22 AS builder
WORKDIR  /go/src/github.com/openshift/oauth-proxy
COPY . .
RUN go build .

FROM registry.ci.openshift.org/ocp/4.22:base-rhel9-minimal
COPY --from=builder /go/src/github.com/openshift/oauth-proxy/oauth-proxy /usr/bin/oauth-proxy
ENTRYPOINT ["/usr/bin/oauth-proxy"]
