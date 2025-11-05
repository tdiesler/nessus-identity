## Configure an insecure registry

Open a shell into the Lima VM:

```bash
LIMA_HOME="$HOME/Library/Application Support/rancher-desktop/lima" "/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/lima/bin/limactl" shell 0
```

Edit the Docker config used by the service:

```bash
sudo vi /etc/docker/daemon.json
{
  "insecure-registries": [
    "k3s-registry:30443",
    "registry.vps4c.eu.ebsi:30443"
  ]
}
```

Restart Docker inside the VM:

```bash
sudo service docker restart
```