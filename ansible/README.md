## Install K3S

Modify inventory.yml

```
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

## Modifying CoreDNS

Pods deployed on K3S do not see /etc/hosts from the host system. Instead, K3S uses
CoreDNS to resolve host names, which we can use to add the required mapping.

```
kubectl -n kube-system edit configmap coredns
...
    hosts /etc/coredns/NodeHosts {
      <host-ip> registry.vps4c.eu.ebsi
      ttl 60                  
      reload 15s              
      fallthrough                        
    }                                    
```
