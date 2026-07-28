FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.19-openshift-4.12 AS builder
WORKDIR  /go/src/github.com/openshift/oauth-proxy
COPY . .
RUN go build .

FROM registry.ci.openshift.org/ocp/builder:rhel-8-base-openshift-4.12
COPY --from=builder /go/src/github.com/openshift/oauth-proxy/oauth-proxy /usr/bin/oauth-proxy
ENTRYPOINT ["/usr/bin/oauth-proxy"]
