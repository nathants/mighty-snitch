#!/bin/bash

if ! which set-opt &>/dev/null; then
    curl --fail --no-progress-meter https://raw.githubusercontent.com/nathants/bootstraps/master/set_opt.sh | /usr/bin/sudo tee /usr/bin/set-opt >/dev/null
    /usr/bin/sudo chmod +x /usr/bin/set-opt
fi

set-opt config-edge.x86_64 CONFIG_SECURITY_NETWORK= y
set-opt config-edge.x86_64 CONFIG_LSM= "snitch,landlock,lockdown,yama,integrity,bpf"
set-opt config-edge.x86_64 CONFIG_SNITCH= y
set-opt config-edge.x86_64 CONFIG_NETFILTER_NETLINK_QUEUE= m
set-opt config-edge.x86_64 CONFIG_NFT_QUEUE= m

sed -i -r 's/^(CONFIG_IO_URING)=.$/# \1 is not set/' config-edge.x86_64
sed -i -r 's/^(CONFIG_.*IPV6.*)=.$/# \1 is not set/' config-edge.x86_64
