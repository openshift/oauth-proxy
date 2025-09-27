FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.24-openshift-4.21 AS builder
WORKDIR  /go/src/github.com/openshift/oauth-proxy
COPY . .
RUN go build .

FROM registry.ci.openshift.org/ocp/4.21:base-rhel9
COPY --from=builder /go/src/github.com/openshift/oauth-proxy/oauth-proxy /usr/bin/oauth-proxy
ENTRYPOINT ["/usr/bin/oauth-proxy"]
