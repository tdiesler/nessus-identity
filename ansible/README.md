## Install K3S

Modify inventory.yml

```
ansible-playbook -i ansible/inventory.yml ansible/step01-k3s-server.yml
```

## Verify that TLS access is working

```
helm upgrade --install whoami ./helm -f ./helm/values-whoami-stage.yaml
curl -vk https://who.nessustech.io
```
