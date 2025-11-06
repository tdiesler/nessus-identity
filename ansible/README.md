## Install K3S

Modify inventory.yml

```
ansible-playbook -i ansible/inventory.yml ansible/step00-prepare-vps.yml
ansible-playbook -i ansible/inventory.yml ansible/step01-install-k3s-server.yml
ansible-playbook -i ansible/inventory.yml ansible/step03-cloudflare-cert.yml
ansible-playbook -i ansible/inventory.yml ansible/step04-install-registry.yml
ansible-playbook -i ansible/inventory.yml ansible/step05-verify-registry.yml
```

## Verify that TLS access is working

```
helm upgrade --install whoami ./helm -f ./helm/values-whoami-stage.yaml
curl -vk https://who.nessustech.io
```
