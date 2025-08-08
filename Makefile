
PROJECT_VERSION := $(shell mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

TARGET ?= local
KUBE_CONTEXT_PROD := "ebsi"
IMAGE_REGISTRY_PROD := "registry.vps6c.eu.ebsi:30443/"

KUBE_CONTEXT_LOCAL := "rancher-desktop"
IMAGE_REGISTRY_LOCAL := ""

IMAGE_NAME := nessusio/ebsi-portal
IMAGE_TAG := "latest"

# Set the IMAGE_REGISTRY based on the deployment TARGET
ifeq ($(TARGET), prod)
  KUBE_CONTEXT := $(KUBE_CONTEXT_PROD)
  IMAGE_REGISTRY := $(IMAGE_REGISTRY_PROD)
endif
ifeq ($(TARGET), local)
  KUBE_CONTEXT := $(KUBE_CONTEXT_LOCAL)
  IMAGE_REGISTRY := $(IMAGE_REGISTRY_LOCAL)
endif

clean:
	@mvn clean

package: clean
	@mvn package -DskipTests

# Build the Docker images
build-images: package
		@docker buildx build --platform linux/amd64 \
			--build-arg PROJECT_VERSION=$(PROJECT_VERSION) \
			-t $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG) \
			-t $(IMAGE_NAME):$(IMAGE_TAG) \
			-f ./ebsi-portal/Dockerfile ./ebsi-portal;
		@if [ $(TARGET) != "local" ]; then \
			echo "Pushing $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG) ..."; \
			docker push $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG); \
		fi

uninstall:
	@helm --kube-context $(KUBE_CONTEXT) uninstall ebsi-portal --ignore-not-found

upgrade: build-images
	@helm --kube-context $(KUBE_CONTEXT) upgrade --install ebsi-portal ./helm -f ./helm/values-ebsi-portal.yaml

upgrade-wallet-api:
	@cd ../waltid-identity && ./gradlew -x jvmTest publishToMavenLocal

# Upgrade WaltID service images (supports build options)
# make upgrade-services BUILD_OPTS=--no-cache
upgrade-services: upgrade-wallet-api
	@cd ../waltid-identity && ./gradlew jibDockerBuild
	@cd ../waltid-identity/docker-compose && \
		docker compose build $(BUILD_OPTS) waltid-dev-wallet && \
		docker compose build $(BUILD_OPTS) waltid-demo-wallet && \
		docker compose build $(BUILD_OPTS) web-portal && \
		docker compose pull opa-server && \
		docker compose pull vc-repo

