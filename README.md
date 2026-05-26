```
vim /etc/netplan/01-network-manager-all.yaml
```
ryu
```
network:
  version: 2
  renderer: networkd

  ethernets:
    ens33:
      dhcp4: no

  bridges:
    br0:
      interfaces:
        - ens33
      addresses:
        - 192.168.8.132/24
      routes:
        - to: default
          via: 192.168.8.2
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
      parameters:
        stp: false
        forward-delay: 0
      openvswitch:
        fail-mode: standalone
        controller:
          addresses:
            - tcp:127.0.0.1:6653
```
```
chmod 600 /etc/netplan/01-network-manager-all.yaml
netplan apply
ovs-vsctl set bridge br0 protocols=OpenFlow13
ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
```

snort
```
network:
  version: 2
  renderer: networkd

  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 192.168.8.133/24
      routes:
        - to: default
          via: 192.168.8.2
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
```
```
chmod 600 /etc/netplan/01-network-manager-all.yaml
netplan apply
```
