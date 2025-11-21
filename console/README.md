
## Reverse SSL terminating proxy

Install the nginx reverse proxy on VPS

```
ansible-playbook -i ansible/inventory.yml ansible/step04-nginx-proxy.yml
```

Open the ssh tunnel

```
ssh -R 127.0.0.1:9000:localhost:9000 core@vps4c.eu.ebsi
```

or more robustly with exit on failure 

```
ssh -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -R 127.0.0.1:9000:localhost:9000 core@vps4c.eu.ebsi
```

Test access and routing

EBSI -> Cloudflare -> VPS:Nginx:8443 -> VPS:9000 --> // SSH Tunnel // --> MacBook:9000

```
python3 -m http.server 9000 --bind 127.0.0.1

curl https://proxy.nessustech.io:8443 
```

If it hangs try this ...

```
sudo lsof -iTCP:9000 -sTCP:LISTEN -n -P
COMMAND     PID USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
sshd    4083774 core    8u  IPv6 29241339      0t0  TCP [::1]:9000 (LISTEN)
sshd    4083774 core    9u  IPv4 29241340      0t0  TCP 127.0.0.1:9000 (LISTEN)

sudo kill 4083774
```
