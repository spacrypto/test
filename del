artix@artix-live /run/media/artix/usb1/linux/ipt
sudo iptables -t filter -N ICMP
sudo iptables -t filter -N TCP
sudo iptables -t filter -N UDP
# INPUT
sudo iptables -t filter -A INPUT -p udp -j UDP
sudo iptables -t filter -A INPUT -p tcp -j TCP
sudo iptables -t filter -A INPUT -p icmp -j ICMP
# OUTPUT
sudo iptables -t filter -A OUTPUT -p udp -j UDP
sudo iptables -t filter -A OUTPUT -p tcp -j TCP
sudo iptables -t filter -A OUTPUT -p icmp -j ICMP
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
sudo iptables -A ICMP -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -t filter -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
sudo iptables -t filter -A INPUT -p tcp -j REJECT --reject-with tcp-reset
sudo iptables -t filter -A INPUT -j REJECT --reject-with icmp-proto-unreachable
sudo iptables -t filter -A INPUT -j DROP
sudo iptables -t filter -A OUTPUT -j DROP
sudo iptables -t filter -A FORWARD -j DROP
#ipv6
sudo ip6tables -t filter -P INPUT ACCEPT
sudo ip6tables -t filter -P OUTPUT ACCEPT
sudo ip6tables -t filter -P FORWARD ACCEPT
sudo ip6tables -t filter -N ICMP
sudo ip6tables -t filter -N TCP
sudo ip6tables -t filter -N UDP
# INPUT
sudo ip6tables -t filter -A INPUT -p udp -j UDP
sudo ip6tables -t filter -A INPUT -p tcp -j TCP
sudo ip6tables -t filter -A INPUT -p icmp -j ICMP
# OUTPUT
sudo ip6tables -t filter -A OUTPUT -p udp -j UDP
sudo ip6tables -t filter -A OUTPUT -p tcp -j TCP
sudo ip6tables -t filter -A OUTPUT -p icmp -j ICMP
sudo ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo ip6tables -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
sudo ip6tables -A INPUT -i lo -j ACCEPT
sudo ip6tables -A OUTPUT -o lo -j ACCEPT
#sudo ip6tables -A FORWARD -o lo -j ACCEPT
sudo ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP
sudo ip6tables -t raw -A PREROUTING -m rpfilter -j ACCEPT
sudo ip6tables -t raw -A PREROUTING -j DROP
sudo ip6tables -A ICMP -p ipv6-icmp --icmpv6-type 128 -m conntrack --ctstate NEW -j ACCEPT
sudo ip6tables -A ICMP -s fe80::/10 -p ipv6-icmp -j ACCEPT
sudo ip6tables -t filter -A INPUT -p udp -j REJECT --reject-with icmp6-adm-prohibited
sudo ip6tables -t filter -A INPUT -p udp -j REJECT --reject-with icmp6-port-unreachable
sudo ip6tables -t filter -A INPUT -p tcp -j REJECT --reject-with tcp-reset
#sudo ip6tables -t filter -A INPUT -p icmpv6 -j REJECT --reject-with icmp6-proto-unreachable
sudo ip6tables -t filter -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
sudo ip6tables -t filter -A INPUT -j DROP
sudo ip6tables -t filter -A OUTPUT -j DROP
sudo ip6tables -t filter -A FORWARD -j DROP
sudo ip6tables-save -f /etc/iptables/ip6tables.rules
sudo iptables-save -f /etc/iptables/iptables.rules
