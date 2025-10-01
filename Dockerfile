FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.22-openshift-4.17 AS builder
WORKDIR  /go/src/github.com/openshift/oauth-proxy
COPY . .
RUN go build .

FROM registry.ci.openshift.org/ocp/builder:rhel-9-base-openshift-4.17
COPY --from=builder /go/src/github.com/openshift/oauth-proxy/oauth-proxy /usr/bin/oauth-proxy
ENTRYPOINT ["/usr/bin/oauth-proxy"]
