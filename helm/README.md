
## Install Persistent Volumes & Secrets

```
kubectl apply -f helm/pvcs/postgres-pvc.yml

kubectl create secret generic postgres-secret \
  --from-literal=POSTGRES_USER=postgres \
  --from-literal=POSTGRES_PASSWORD=postgres

kubectl create secret generic ebsi-secret \
  --from-literal=PREAUTHORIZED_PIN=1234
```

## Install Identity Service

```
helm upgrade --install identity ./helm -f ./helm/values-services-local.yaml
```

