
PROJECT_VERSION := $(shell mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

TARGET ?= dev

KUBE_CONTEXT_DEV := "rancher-desktop"
IMAGE_REGISTRY_DEV := ""

KUBE_CONTEXT_STAGE := "ebsi"
IMAGE_REGISTRY_STAGE := "registry.vps6c.eu.ebsi:30443/"

IMAGE_TAG := "latest"

# Set the IMAGE_REGISTRY based on the deployment TARGET
ifeq ($(TARGET), dev)
  KUBE_CONTEXT := $(KUBE_CONTEXT_DEV)
  IMAGE_REGISTRY := $(IMAGE_REGISTRY_DEV)
endif
ifeq ($(TARGET), stage)
  KUBE_CONTEXT := $(KUBE_CONTEXT_STAGE)
  IMAGE_REGISTRY := $(IMAGE_REGISTRY_STAGE)
  JIB_PLATFORM_OPTS := "-Djib.from.platforms=linux/amd64"
endif

CAROOT_DIR := $(shell mkcert -CAROOT)

check-docker:
	@docker --version || echo "docker command failed"

clean:
	@mvn clean

package: clean
	@mvn package -Pebsi -DskipTests

# Build the Docker images
nessus-images: package
		@docker buildx build --platform linux/amd64 \
			--build-arg PROJECT_VERSION=$(PROJECT_VERSION) \
			-t $(IMAGE_REGISTRY)nessusio/console:$(IMAGE_TAG) \
			-t nessusio/console:$(IMAGE_TAG) \
			-f ./console/Dockerfile ./console
		@docker buildx build --platform linux/amd64 \
			--build-arg PROJECT_VERSION=$(PROJECT_VERSION) \
			-t $(IMAGE_REGISTRY)nessusio/ebsi-portal:$(IMAGE_TAG) \
			-t nessusio/ebsi-portal:$(IMAGE_TAG) \
			-f ./ebsi/Dockerfile ./ebsi
		@if [ $(TARGET) == "stage" ]; then \
			docker push $(IMAGE_REGISTRY)nessusio/console:$(IMAGE_TAG); \
			docker push $(IMAGE_REGISTRY)nessusio/ebsi-portal:$(IMAGE_TAG); \
		fi

waltid-install:
	@cd ../waltid-identity && ./gradlew -x jvmTest publishToMavenLocal

# Build WaltID images (only needed for unreleased PRs)
waltid-images: waltid-install
	@cd ../waltid-identity && \
		./gradlew :waltid-services:waltid-wallet-api:jibDockerBuild $(JIB_PLATFORM_OPTS)
	@if [ $(TARGET) == "stage" ]; then \
  		docker tag waltid-wallet-api:1.0.0-SNAPSHOT $(IMAGE_REGISTRY)waltid-wallet-api:1.0.0-SNAPSHOT; \
		docker push $(IMAGE_REGISTRY)waltid-wallet-api:1.0.0-SNAPSHOT; \
	fi

images: waltid-images nessus-images

run-all: package
	trap 'kill 0' INT TERM; \
	(mvn -pl console exec:java) & \
	wait

upgrade:
	@helm --kube-context $(KUBE_CONTEXT) upgrade --install nessus-identity ./helm -f ./helm/values-services-$(TARGET).yaml

uninstall:
	@helm --kube-context $(KUBE_CONTEXT) uninstall nessus-identity --ignore-not-found
