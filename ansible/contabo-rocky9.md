
* Rocky 9

### Setup the core user

```
ssh root@vps4c.eu.ebsi

HOSTNAME=vps4c.eu.ebsi
RSA_PUBKEY="ssh-rsa ..."

dnf install -y bind-utils buildah git httpd-tools jq tar

NUSER=core
useradd -G root -m $NUSER -s /bin/bash
mkdir /home/$NUSER/.ssh
echo "${RSA_PUBKEY}" > /home/$NUSER/.ssh/authorized_keys
chmod 700 /home/$NUSER/.ssh
chown -R $NUSER.$NUSER /home/$NUSER/.ssh

cat << EOF > /etc/sudoers.d/user-privs-$NUSER
$NUSER ALL=(ALL:ALL) NOPASSWD: ALL
EOF

echo $HOSTNAME | sudo tee /etc/hostname
sudo hostname -b $HOSTNAME

echo 'export PS1="[\u@\H \W]\$ "' >> /home/$NUSER/.bash_profile
```

### Harden SSH access

```
# ------------------------------------------------------------------------------
# SSH login to core@xxx.xxx.xxx.xxx from another terminal
# ------------------------------------------------------------------------------

# Assign a random SSH port above 10000
rnd=$((10000+$RANDOM%20000))
sed -i "s/#Port 22$/Port $rnd/" /etc/ssh/sshd_config

# Disable password authentication
sed -i "s/PasswordAuthentication yes$/PasswordAuthentication no/" /etc/ssh/sshd_config

# Disable root login
sed -i "s/PermitRootLogin yes$/PermitRootLogin no/" /etc/ssh/sshd_config

# Disable X11Forwarding
sed -i "s/X11Forwarding yes$/X11Forwarding no/" /etc/ssh/sshd_config

cat /etc/ssh/sshd_config | egrep "^Port"
cat /etc/ssh/sshd_config | egrep "PasswordAuthentication"
cat /etc/ssh/sshd_config | egrep "PermitRootLogin"
cat /etc/ssh/sshd_config | egrep "X11Forwarding"

# SELinux — the port must be labeled for SSH
semanage port -a -t ssh_port_t -p tcp $rnd

systemctl restart sshd
```

### Disable SELinux

```
sed -i "s/^SELINUX=enforcing/SELINUX=disabled/" /etc/selinux/config

# Persistently set the bootloader to boot with selinux=0
grubby --update-kernel ALL --args selinux=0
```