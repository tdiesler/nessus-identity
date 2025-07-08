
## Reverse SSL terminating proxy

Install the nginx reverse proxy on VPS

```
ansible-playbook -i ansible/inventory.yml ansible/step04-nginx-proxy.yml
```

Open the ssh tunnel

```
ssh -R 0.0.0.0:9090:localhost:9090 core@vps6c.eu.ebsi
```

Test access and routing

EBSI -> Cloudflare -> VPS:Nginx:8443 -> VPS:9090 --> // SSH Tunnel // --> MacBook:9090:Ktor

```
curl https://proxy.nessus-tech.io:8443 
```
