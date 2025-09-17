
Here there are some requirements already included in the installation script and left here as documentation.

### Network Setup

Minikube by default only allows the access to deployed services (i.e. to the minikube network) from the host where minikube container is running,
but not from any local network (other computers in the network) or Internet (if there is any router connected).
It is required to open the ports 80 and 443 to be reachable from local network in order to:
 - access from other computers to the services of mininode
 - allow Let's Encrypt server to access from Internet do the challenge required to give you the certificates for HTTPS communications.

These two ports from the host must be binded and any message received there must be redirected to the ingress-nginx-controller service running in minikube.
We can do that with NAT rules using iptables or with kubectl port-forward.

#### NAT with iptables (recommended)
Let's get first the URL to access the ingress-nginx-controller service from the host:
`minikube service ingress-nginx-controller -n ingress-nginx`

The output is like this:
```
|---------------|--------------------------|-------------|---------------------------|
|   NAMESPACE   |           NAME           | TARGET PORT |            URL            |
|---------------|--------------------------|-------------|---------------------------|
| ingress-nginx | ingress-nginx-controller | http/80     | http://192.168.49.2:30906 |
|               |                          | https/443   | http://192.168.49.2:31630 |
|---------------|--------------------------|-------------|---------------------------|
```
The minikube proxy address is 192.168.49.2 and nodeports are 30906 and 31630 (which are redirected at the end to the target ports in the container)

So let's add iptables rules to forward external ports 80 and 443 (i.e. host ports, not the target ports) to the ingess-nginx-controller service.

The first rules to be added will do NAT for all packets with destination ports 80 and 443, 
changing that destination of the packets to the proxy address and the corresponding nodeport of the service.
```
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.49.2:30906
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.168.49.2:31630
```
We can confirm the rules are added with `sudo iptables --list -t nat` (see in the PREROUTING chain).

Then we must add another rules to accept forwarded packets (matching with the destination address and ports changed in PREROUTING).
Note these rules are added in the first position (-I <chain> <position>) because the sub-chain "DOCKER-FORWARD" added by docker drops all packets.
```
sudo iptables -I FORWARD 1 -p tcp -d 192.168.49.2 --dport 30906 -j ACCEPT
sudo iptables -I FORWARD 1 -p tcp -d 192.168.49.2 --dport 31630 -j ACCEPT
```
We can confirm the rules are added with `sudo iptables --list` (see in the FORWARD chain).

MASQUERADE rules are required to correct packets in the opposite direction, from the service in minikube to the external,
changing the origin address to the host address.
However docker already adds these rules, so actually we don't need to add them.
```
# sudo iptables -t nat -A POSTROUTING -s 192.168.49.0/24 ! -o br-189d1a7e3c1c -j MASQUERADE
```
Packets matching with the source network 192.168.49.0/24 (minikube) 
and any other output interface (`!` prefix to negate, and br-189d1a7e3c1c is the minikube network interface) will be masqueraded.
We can confirm the rules are added with `sudo iptables --list -t nat` (see in the POSTROUTING chain).

Finally we have to make the rules persistent, otherwise they will be lost on reboot.  
We can just add the previous commands in a script file like this:
/etc/network/if-pre-up.d/mininode-iptables-rules

All the scripts in that path will be executed when the network gets up.

The content (inserting the rules only if exists, checking with `-C`):
```
#!/bin/sh
iptables -t nat -C PREROUTING ... || iptables -t nat -A PREROUTING ...
iptables -t nat -C PREROUTING ... || iptables -t nat -A PREROUTING ...

iptables -C FORWARD ... || iptables -I FORWARD 1 ...
iptables -C FORWARD ... || iptables -I FORWARD 1 ...
```
And then add execution permission to it:
`chmod +x /etc/network/if-pre-up.d/mininode-iptables-rules`


#### kubectl port-forward (alternative) 
We can alternatively achieve the same thing with a proxy provided by kubectl port-forward:
```
# port-forward can not directly use the host ports 80 and 443 because they are in the OS-reserved range and minikube is not running as root, 
# so let's redirect these ports to arbitrary intermediate ports 33421 and 33422 with iptables (as root)
sudo iptables -t nat -A PREROUTING  -p tcp --dport 80 -j REDIRECT --to-port 33421
sudo iptables -t nat -A PREROUTING  -p tcp --dport 443 -j REDIRECT --to-port 33422

# And then forward the host ports 33421 and 33422 on any interface (address 0.0.0.0) to the ports 80 and 443 of the service in minikube.
minikube kubectl -- port-forward service/ingress-nginx-controller -n ingress-nginx --address=0.0.0.0  33421:80 &
minikube kubectl -- port-forward service/ingress-nginx-controller -n ingress-nginx --address=0.0.0.0  33422:443 &
```
Note every kubectl port-forward command launches a process in background 
and that is one of the reasons why the other solution (NAT with iptables) is recommended.


