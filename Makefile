
PROJECT_VERSION := $(shell mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

TARGET ?= dev

IMAGE_TAG := "latest"

# Set the IMAGE_REGISTRY based on the deployment TARGET
ifeq ($(TARGET), local)
  KUBE_CONTEXT := "rancher-desktop"
else ifeq ($(TARGET), dev)
  KUBE_CONTEXT := "rancher-desktop"
else ifeq ($(TARGET), stage)
  KUBE_CONTEXT := "ebsi"
  IMAGE_REGISTRY := "registry.vps6c.eu.ebsi:30443/"
  JIB_PLATFORM_OPTS := "-Djib.from.platforms=linux/amd64"
else
  $(error Unknown TARGET '$(TARGET)')
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
	@cd ../waltid-identity && ./gradlew -x jvmTest clean publishToMavenLocal

# Build WaltID images (only needed for unreleased PRs)
waltid-images: waltid-install
	@cd ../waltid-identity && \
		./gradlew :waltid-services:waltid-wallet-api:jibDockerBuild $(JIB_PLATFORM_OPTS)
	@if [ $(TARGET) == "stage" ]; then \
  		docker tag waltid-wallet-api:1.0.0-SNAPSHOT $(IMAGE_REGISTRY)waltid-wallet-api:1.0.0-SNAPSHOT; \
		docker push $(IMAGE_REGISTRY)waltid-wallet-api:1.0.0-SNAPSHOT; \
	fi

images: waltid-images nessus-images

keycloak:
	@cd ../keycloak && ./mvnw -pl quarkus/deployment,quarkus/dist -am -DskipTests clean install

# [TODO #43606] Unable to start Keycloak from built quarkus-run.jar
# https://github.com/keycloak/keycloak/issues/43606
# https://github.com/keycloak/keycloak/blob/main/docs/building.md#starting-keycloak
#keycloak-run:
#	@cd ../keycloak && java -Dkc.config.built=true -jar server/target/lib/quarkus-run.jar start-dev --features=oid4vc-vci --bootstrap-admin-username=admin --bootstrap-admin-password=admin

run-services: package
	trap 'kill 0' INT TERM; \
	(mvn -pl console exec:java) & \
	wait

upgrade:
	@helm --kube-context $(KUBE_CONTEXT) upgrade --install nessus-identity ./helm -f ./helm/values-services-$(TARGET).yaml

uninstall:
	@helm --kube-context $(KUBE_CONTEXT) uninstall nessus-identity --ignore-not-found
