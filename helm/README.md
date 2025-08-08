
## Prepare Postgres Service

```
kubectl apply -f helm/pvcs/postgres-pvc.yml

kubectl create secret generic postgres-secret \
  --from-literal=POSTGRES_USER=postgres \
  --from-literal=POSTGRES_PASSWORD=postgres

kubectl create secret generic ebsi-secret \
  --from-literal=PREAUTHORIZED_PIN=1234
```

## Prepare Keycloak Service

Install TLS edge certificate

```
brew install mkcert nss

mkcert --install
mkcert "localtest.me" "*.localtest.me"
mkdir -p helm/tls && mv localtest.* helm/tls/

kubectl delete secret edge-tls --ignore-not-found=true
kubectl create secret tls edge-tls \
    --cert=helm/tls/localtest.me+1.pem \
    --key=helm/tls/localtest.me+1-key.pem
```

Keycloak admin secret

```
kubectl delete secret keycloak-admin --ignore-not-found=true
kubectl create secret generic keycloak-admin \
  --from-literal=ADMIN_USERNAME=admin \
  --from-literal=ADMIN_PASSWORD=admin
```

## Install Identity Services

```
helm upgrade --install nessus-identity ./helm -f ./helm/values-services-local.yaml
helm uninstall nessus-identity
```

## Keycloak post-install setup

```
helm upgrade --install identity ./helm -f ./helm/values-services-local.yaml
```

