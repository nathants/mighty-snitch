# mighty-snitch

## why

noticing and preventing network requests should be easy.

## how

interactively filter network requests with rules and visual prompts.

## what

a [linux security module](https://www.kernel.org/doc/html/latest/security/lsm.html) communicates via [netlink](https://man7.org/linux/man-pages/man7/netlink.7.html) with the userspace [snitch](https://github.com/nathants/mighty-snitch/blob/master/snitch/snitch.c) on each [sendmsg](https://man7.org/linux/man-pages/man3/sendmsg.3p.html)/[recvmsg](https://man7.org/linux/man-pages/man3/recvmsg.3p.html).

snitch decides whether to allow or deny the network request.

rules are checked. if no rule exists, a visual prompt is displayed to the user.

finally snitch responds to the kernel and the request is allowed or denied.

## demo

![](https://github.com/nathants/mighty-snitch/raw/master/demo.gif)

![](https://github.com/nathants/mighty-snitch/raw/master/mobile.jpg)

## hardware

the primary test environments are [alpine](https://alpinelinux.org/) x86_64 and [postmarketos](https://postmarketos.org/) arm64.

the primary test devices are [thinkpad x1](https://www.lenovo.com/us/en/c/laptops/thinkpad/thinkpadx1) and [oneplus 6t](https://www.oneplus.com/6t).

## prior art

[little-snitch](https://www.obdev.at/products/littlesnitch/index.html) which introduced me to this concept.

[open-snitch](https://github.com/evilsocket/opensnitch) which introduced me to [nfq](https://www.netfilter.org/projects/libnetfilter_queue/).

[tiny-snitch](https://github.com/nathants/tinysnitch) which helped me understand what is possible with [nfq](https://www.netfilter.org/projects/libnetfilter_queue/) and [bpftrace](https://github.com/iovisor/bpftrace).

[uslm](https://github.com/argussecurity/ulsm) which helped me understand what is possible with [lsm](https://www.kernel.org/doc/html/latest/security/lsm.html).

## design

mighty-snitch uses [lsm](https://www.kernel.org/doc/html/latest/security/lsm.html) instead of [nfq](https://www.netfilter.org/projects/libnetfilter_queue/) to filter network requests.

the primary advantage is that it has direct access to the pid, executable, and commandline of the process making the request.

the primary disadvantage is that it requires a custom kernel.

the visual prompt is a terminal [application](https://github.com/nathants/mighty-snitch/blob/master/snitch-prompt/snitch-prompt) which responds to keyboard input. a new terminal is launched for each prompt and exits after y/n are pressed. [st](https://st.suckless.org/) is used on x86_64 and [foot](https://codeberg.org/dnkl/foot) is used on arm64, though any terminal should work.

the systems fails closed. when snitch isn't running, network requests are not possible.

dns packets received on udp 53 are read via [nfq](https://www.netfilter.org/projects/libnetfilter_queue/) so that rules can specify domains in addition to ipv4 addresses.

## constraints

the following are simplifying constraints. other configurations should be possible.

- ipv6 is disabled.

- io_uring is disabled.

- nftables rules are replaced when snitch starts.

- iptables rules should be empty.

- all other lsm are disabled.

- kernel commandline parameters for lsm are ignored.

## rules

snitch creates a rules file: `~/.snitch.rules`

when this file is edited, snitch reloads the rules.

typically rules are created by choosing the `forever` duration in the visual prompt, but can also be directly added to the rules file.

address can be a wildcard up to three subdomains.

commandline can be a wildcard.

here are the rules for firefox to deny all the unprompted connections it makes:

```
send  deny  /usr/lib/firefox/firefox  content-signature-2.cdn.mozilla.net    443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  content-signature-2.cdn.mozilla.net    80   tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  contile.services.mozilla.com           443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  firefox.settings.services.mozilla.com  443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  firefox.settings.services.mozilla.com  443  udp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  getpocket.cdn.mozilla.net              443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  location.services.mozilla.com          443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  mozilla.cloudflare-dns.com             443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  normandy.cdn.mozilla.net               443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  push.services.mozilla.com              443  tcp  /usr/lib/firefox/firefox
send  deny  /usr/lib/firefox/firefox  shavar.services.mozilla.com            443  tcp  /usr/lib/firefox/firefox
```

## install x86_64

copy latest wget urls from: https://github.com/nathants/mighty-snitch/releases

```bash
cd /tmp
wget linux-edge-*.apk
wget linux-edge-dev-*.apk
wget me@nathants.com-*.rsa.pub
sudo mv *.pub /etc/apk/keys/
sudo apk add *.apk
sudo reboot

cd ~
git clone https://github.com/nathants/mighty-snitch

cd ~/might-snitch/snitch-prompt
sudo pip install .

cd ~/mighty-snitch/snitch
bash snitch.sh
```

## install arm64

copy latest wget urls from: https://github.com/nathants/mighty-snitch/releases

```bash
cd /tmp
wget linux-postmarketos-qcom-sdm845-*.apk
wget pmos@local-*.rsa.pub
sudo mv *.pub /etc/apk/keys/
sudo apk add *.apk
sudo reboot

cd ~
git clone https://github.com/nathants/mighty-snitch

cd ~/might-snitch/snitch-prompt
sudo pip install .

cd ~/mighty-snitch/snitch
bash snitch.sh
```

## build on aws and install x86_64

```bash
sudo apk add go
go install github.com/nathants/libaws@latest
export PATH=$PATH:$(go env GOPATH)/bin

export MIGHTY_SNITCH_S3_BUCKET=$NAME
export MIGHTY_SNITCH_AWS_ACCOUNT=$ACCOUNT_NUMBER
export MIGHTY_SNITCH_PUBKEY_CONTENT=$(cat ~/.ssh/id_ed25519.pub)

cd ~
git clone https://github.com/nathants/mighty-snitch

cd ~/might-snitch/kernel/alpine
bash build.sh
sudo mv /tmp/abuild/*.pub /etc/apk/keys/
sudo apk add /tmp/packages/*/*/*.apk
sudo reboot

cd ~/mighty-snitch/snitch-prompt
sudo pip install .

cd ~/mighty-snitch/snitch
bash snitch.sh
```

## build on aws and install arm64

```bash

sudo apk add go
go install github.com/nathants/libaws@latest
export PATH=$PATH:$(go env GOPATH)/bin

export MIGHTY_SNITCH_S3_BUCKET=$NAME
export MIGHTY_SNITCH_AWS_ACCOUNT=$ACCOUNT_NUMBER
export MIGHTY_SNITCH_PUBKEY_CONTENT=$(cat ~/.ssh/id_ed25519.pub)

cd ~
git clone https://github.com/nathants/mighty-snitch

cd ~/mighty-snitch/kernel/alpine-sdm845
bash build.sh
sudo mv /tmp/*.pub /etc/apk/keys/
sudo apk add /tmp/*.apk
sudo reboot

cd ~/mighty-snitch/snitch-prompt
sudo pip install .

cd ~/mighty-snitch/snitch
bash snitch.sh
```
