
## Build Docker Images

Checkout this project and [waltid-identity](https://github.com/tdiesler/waltid-identity.git) 
with branch [nessus-dev](https://github.com/tdiesler/waltid-identity/tree/nessus-dev)

```
git clone -b nessus-dev https://github.com/tdiesler/waltid-identity.git
```

Build and deploy steps are conveniently encoded in the [Makefile](./Makefile). Run ...

```
make images
```

## Prepare K8S Environment

Create Postgres username/password secret

```
KEYCLAOK_PASSWORD="admin"
POSTGRES_PASSWORD="changeme"

kubectl delete secret postgres-secret --ignore-not-found=true
kubectl create secret generic postgres-secret \
  --from-literal=POSTGRES_USER=postgres \
  --from-literal=POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
```

Create Keycloak admin/password secret

```
kubectl delete secret keycloak-secret --ignore-not-found=true
kubectl create secret generic keycloak-secret \
  --from-literal=ADMIN_USERNAME=admin \
  --from-literal=ADMIN_PASSWORD=${KEYCLAOK_PASSWORD}
```

Create and install TLS edge certificate

```
brew install mkcert nss

# Make sure the mkcert root CA is trusted
mkcert --install

mkcert "localtest.me" "*.localtest.me"
mkdir -p helm/tls && mv localtest.* helm/tls

kubectl delete secret edge-tls --ignore-not-found=true
kubectl create secret tls edge-tls \
    --cert=helm/tls/localtest.me+1.pem \
    --key=helm/tls/localtest.me+1-key.pem

# Java does not use the system truststore (i.e. mkcert --install is not enough)
# Import the mkcert rootCA.pem to the Java truststore
keytool -delete -cacerts -alias mkcert-root -storepass changeit
keytool -importcert -cacerts -alias mkcert-root -storepass changeit -noprompt \
    -file "$(mkcert -CAROOT)/rootCA.pem"
```
