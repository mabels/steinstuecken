# steinstuecken
An infrastructure to maintain network enclaves which could communicate to the internet via whitelisting.


# commandline

```sh
$ docker run  -ti ghcr.io/mabels/steinstuecken:latest --help
Usage of steinstuecken:
      --alternate-force         override alternate-path
      --alternate-path string   if iptable-path to alternate iptables (default "/alternate")
      --chain-name string       iptables chain name (default "STEINSTUECKEN")
      --disable-ipv4            do not generate ipv4 rules
      --disable-ipv6            do not generate ipv6 rules
      --first-rule              insert rule as first rule in chain
      --iptable-type string     empty means use system -- iptables type (nft or legacy)
      --no-final-drop           do not drop packets that do not match any rule
      --src-path string         if iptable-path to src iptables (default "/sbin")
      --target stringArray      target to connect to
pflag: help requested
```


# run docker

* --network host is needed to set the filter to node which should be the default gateway
* --privileged is needed to set the iptables rules

```sh
   docker run  --network host --privileged    -ti ghcr.io/mabels/steinstuecken:latest
```

# target examples

    - 'sken://www.google.de./?nameserver=192.168.128.2&port=443,80&snat4=192.168.44.3&type=A&type=AAAA'
    - 'sken://vercel.com.:443/?forward4=4&nonStateful&inIface=eno1&outIface=eno1&nameserver=8.8.8.8&nameserver=8.8.4.4'
    - 'sken://dl-cdn.alpinelinux.org./'
    - 'sken://192.168.128.0/24?port=53/udp&port=255/icmp&port=22,443,80/tcp&nonStateful'
    - 'sken://[fe80::1]/64?port=53/udp&port=22,443,80/tcp&nonStateful'

# url schema

    - schema sken
    - hostname
        * dns-name
        * ipv4
        * ipv6
    - port ignored default 443
    - path
       - if hostname ip number than prefix like /24 or /64
    - query
        * port multiple and (\d+[,|]*)+[/{udp/tcp/icmp}]      protocol is default 443/tcp
        example 22,80,443/tcp
        * inIface string to -i parameter iptables
        * outIface string to -o parameter iptables
        * nonStateful ignore conntrack module
        * snat4 ipv4 generate a SNAT rule with to-source
        * snat6 ipv6 generate a SNAT rule with to-source
        * masq generate a MASQUARED rule
