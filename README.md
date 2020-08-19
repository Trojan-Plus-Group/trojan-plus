# Trojan Plus Project
![](https://raw.githubusercontent.com/wiki/Trojan-Plus-Group/trojan-plus//trojan_plus_logo.png)

## Introduction

It's compatible with [original trojan](https://github.com/trojan-gfw/trojan) with following **experimental features**:

* [NAT for udp](https://github.com/Trojan-Plus-Group/trojan-plus/wiki/Configure#nat-config)
* [Pipeline Mode to decrease latency](https://github.com/yuchting/trojan/wiki/Why-we-need-Pipeline-mode)
* [Loadbalance for 2+ servers to increase bandwidth](https://github.com/yuchting/trojan/wiki/Why-we-need-load-balance-mode)
* [Proxy ICMP message](https://github.com/Trojan-Plus-Group/trojan-plus/wiki/Can-we-proxy-ICMP-message-(To-transfer-ping))

Trojan plus can be used as client or server to connect original trojan server or client, so if you just upgrade trojan plus binary with old config file, it can work all the same, we has optimized original trojan project a lot, especially in NAT mode.

Trojan plus' experimental features need to be used/enabled **both server-end and client-end**, so if you want to use them, please update both ends into trojan plus. In the other words, if you don't use/enable experimental features, you can use trojan plus in single end to adapt the original trojan.

Trojan plus has a different belief to original trojan, **running effective with more features first** instead of project simplification (origin trojan don't want to add unnecessary features, they want to [keep the project simple](https://github.com/trojan-gfw/trojan/blob/master/CONTRIBUTING.md#pull-requests)). Under this trojan plus' belief, for Android lib, we even write a low level TUN tunnel interface to get better effective a little bit, rather than integrate/use other 3rd system directly such as tun2socks or clash (such as [shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android) and [Igniter](https://github.com/trojan-gfw/igniter)).

Trojan plus project's best running environment is Linux system in NAT mode (might be known as transparent proxy), it would be better if you has a software-router gateway instead of OpenWrt in a weak hardware. That's to say trojan plus is prepared for company's gateway for handreds of devices proxying.  

## Compiling

### Requirement

* [C++17 supporting](https://en.wikipedia.org/wiki/C%2B%2B17) 
  - GNU gcc 7.0.0+ in linux
  - or Visual Studio 2017(15.7)+ in Windows
  - or Clang 5+ (XCode 6+) in MacOS
* [CMake](https://cmake.org/) >= 3.7.2
* [Boost](http://www.boost.org/) >= 1.72.0 ( 1.73.0 recommend )
* [OpenSSL](https://www.openssl.org/) >= 1.1.0 ( 1.1.1g recommend)
* [libmysqlclient](https://downloads.mariadb.orgd)

Here is a [compiling guide](https://github.com/Trojan-Plus-Group/trojan-plus/wiki/Compiling) to guide you compiling trojan plus in CentOS, you can copy and modify it for your system.

### Configure

Here's a [config wiki](https://github.com/Trojan-Plus-Group/trojan-plus/wiki/Configure) for fully introduction.

### Open Source Code

* [trojan in GPLv3](https://github.com/trojan-gfw/trojan/blob/master/LICENSE)
* [badvpn (lwip part)](https://github.com/Trojan-Plus-Group/badvpn)
* [boost.org](https://www.boost.org/users/license.html)
* [openssl](https://www.openssl.org/)
* [mariadb](https://mariadb.com/kb/en/legal-documents-mariadb-license/)
* [GSL](https://github.com/microsoft/GSL)

## License

We follow original trojan's [GPLv3](LICENSE)
