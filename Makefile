
PROJECT_VERSION := $(shell mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

# Default target if not set
# Keep in sync with oid4vci-setup
TARGET ?= local

DOCKER_IMAGE_TAG := "latest"

KEYCLOAK_DIR ?= ../keycloak
KEYCLOAK_HOME_DIR ?= $(KEYCLOAK_DIR)/quarkus/dist/target/keycloak-999.0.0-SNAPSHOT
KEYCLOAK_FEATURES ?= "client-auth-abca,oid4vc-vci,oid4vc-vci-preauth-code"

# Set the IMAGE_REGISTRY based on the deployment TARGET
ifeq ($(TARGET), local)
  KUBE_CONTEXT := "rancher-desktop"
  KEYCLOAK_HOSTNAME ?= "http://localhost:8080"
else ifeq ($(TARGET), ngrok)
  NGROK_URL ?= "https://buzz-junior-passing.ngrok-free.dev"
  KEYCLOAK_HOSTNAME ?= $(NGROK_URL)
else ifeq ($(TARGET), proxy)
  KEYCLOAK_HOSTNAME ?= "https://keycloak.nessustech.io:8443"
else ifeq ($(TARGET), stage)
  KUBE_CONTEXT := "ebsi"
  IMAGE_REGISTRY := "registry.nessustech.io/"
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
			-t $(IMAGE_REGISTRY)nessusio/console:$(DOCKER_IMAGE_TAG) \
			-t nessusio/console:$(DOCKER_IMAGE_TAG) \
			-f ./console/Dockerfile ./console
		@if [ $(TARGET) == "stage" ]; then \
			docker push $(IMAGE_REGISTRY)nessusio/console:$(DOCKER_IMAGE_TAG)
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

keycloak-build:
	@cd $(KEYCLOAK_DIR) && ./mvnw -pl 'quarkus/dist,!crypto/fips1402,tests,testsuite/integration-arquillian/tests/base' -am -DskipTests clean install
	@tar xzf $(KEYCLOAK_DIR)/quarkus/dist/target/keycloak-999.0.0-SNAPSHOT.tar.gz -C $(KEYCLOAK_DIR)/quarkus/dist/target

keycloak-image: keycloak-build
	@cd $(KEYCLOAK_DIR)/quarkus/container && cp ../dist/target/keycloak-999.0.0-SNAPSHOT.tar.gz . && \
		docker buildx build --platform linux/amd64 --build-arg KEYCLOAK_DIST=keycloak-999.0.0-SNAPSHOT.tar.gz -t $(IMAGE_REGISTRY)keycloak:latest .
	@if [ $(TARGET) == "stage" ]; then \
		docker push $(IMAGE_REGISTRY)keycloak:latest; \
	fi

# Append debug log options e.g.
# 	--log-level=org.keycloak.protocol.oid4vc:debug,org.keycloak.services:debug,org.keycloak.events:debug,org.keycloak.authentication:debug,root:info
keycloak-run:
	@KC_HOME="$(KEYCLOAK_HOME_DIR)" && PRINT_ENV="true" \
		$${KC_HOME}/bin/kc.sh start-dev
			--bootstrap-admin-username=admin \
			--bootstrap-admin-password=admin \
			--features=oid4vc-vci

keycloak-run-ngrok:
	@if [ -z "$(NGROK_URL)" ]; then echo "Set NGROK_URL to the public https ngrok URL"; exit 1; fi
	@KC_HOME="$(KEYCLOAK_HOME_DIR)" && PRINT_ENV="true" \
		$${KC_HOME}/bin/kc.sh start-dev \
			--hostname=$(NGROK_URL) \
			--proxy-headers=xforwarded \
			--bootstrap-admin-username=admin \
			--bootstrap-admin-password=admin \
			--features=$(KEYCLOAK_FEATURES)

keycloak-run-proxy:
	@KC_HOME="$(KEYCLOAK_HOME_DIR)" && PRINT_ENV="true" \
		$${KC_HOME}/bin/kc.sh start \
			--hostname=$(KEYCLOAK_HOSTNAME) \
			--proxy-headers=xforwarded \
		    --db=postgres \
		    --db-url=jdbc:postgresql://localhost:32543/keycloak \
		    --db-username=postgres \
		    --db-password=changeme \
			--bootstrap-admin-username=admin \
			--bootstrap-admin-password=admin \
			--features=$(KEYCLOAK_FEATURES)

# -Pauth-server-quarkus
keycloak-tests:
	@cd $(KEYCLOAK_DIR) && \
		mvn -pl tests/base clean test -Dtest='org.keycloak.tests.oid4vc.**'

keycloak-testsuite:
	@cd $(KEYCLOAK_DIR) && \
		mvn -pl testsuite/integration-arquillian/tests/base clean test -Dtest='org.keycloak.testsuite.oid4vc.**'

run-services: package
	trap 'kill 0' INT TERM; \
	(mvn -pl console exec:java) & \
	wait

upgrade:
	@helm --kube-context $(KUBE_CONTEXT) upgrade --install nessus-identity ./helm -f ./helm/values-services-$(TARGET).yaml

uninstall:
	@helm --kube-context $(KUBE_CONTEXT) uninstall nessus-identity --ignore-not-found
