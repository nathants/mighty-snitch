#!/bin/bash

if ! which set-opt &>/dev/null; then
    curl --fail --no-progress-meter https://raw.githubusercontent.com/nathants/bootstraps/master/set_opt.sh | /usr/bin/sudo tee /usr/bin/set-opt >/dev/null
    /usr/bin/sudo chmod +x /usr/bin/set-opt
fi

grep CONFIG_SECURITY_NETWORK=y config-edge.x86_64
grep CONFIG_NETFILTER_NETLINK_QUEUE=m config-edge.x86_64
grep CONFIG_NFT_QUEUE=m config-edge.x86_64

sed -i -r 's/^CONFIG_LSM="([^"]+)"/CONFIG_SNITCH=y\nCONFIG_LSM="snitch,\1"/' config-edge.x86_64
sed -i -r 's/^(CONFIG_IO_URING)=.$/# \1 is not set/' config-edge.x86_64
sed -i -r 's/^(CONFIG_.*IPV6.*)=.$/# \1 is not set/' config-edge.x86_64
