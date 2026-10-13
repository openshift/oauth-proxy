.PHONY: all

# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
    golang.mk \
    targets/openshift/deps-gomod.mk \
    targets/openshift/images.mk \
)

IMAGE_REGISTRY?=registry.svc.ci.openshift.org

# This will call a macro called "build-image" which will generate image specific targets based on the parameters:
# $0 - macro name
# $1 - target name
# $2 - image ref
# $3 - Dockerfile path
# $4 - context directory for image build
# It will generate target "image-$(1)" for building the image and binding it as a prerequisite to target "images".
$(call build-image,ocp-oauth-proxy,$(IMAGE_REGISTRY)/ocp/4.6:oauth-proxy,./Dockerfile,.)

clean:
	$(RM) ./oauth-proxy
.PHONY: clean

GO_BUILD_PACKAGES := .
# avoid the test/ directory only containing the e2e tests
GO_TEST_PACKAGES :=./ ./api/... ./cookie/... ./providers/... ./util/...

test-e2e: GO_TEST_PACKAGES :=./test/e2e/...
test-e2e: GO_TEST_FLAGS += -v
test-e2e: GO_TEST_FLAGS += -timeout 3h
test-e2e: GO_TEST_FLAGS += -count 1
test-e2e: GO_TEST_FLAGS += -p 1
test-e2e: test-unit
.PHONY: test-e2e
