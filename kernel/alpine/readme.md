upstream source: https://gitlab.alpinelinux.org/alpine/aports/-/tree/master/community/linux-edge

when updating kernel configs, take upstream, and then ensure the following:

- `CONFIG_SECURITY_NETWORK=y`

- `CONFIG_LSM="snitch,..."` prepend "snitch" to this list

- `CONFIG_SNITCH=y`

- `CONFIG_NETFILTER_NETLINK_QUEUE=m`

- `CONFIG_NFT_QUEUE=m`

- `CONFIG_HIDRAW=y`

- `CONFIG_USB_HIDDEV=y`

- `# CONFIG_IO_URING is not set`

- disable ipv6:
  ```bash
  ls config-edge.* | while read config; do
      sed -i -r 's/^(CONFIG_.*IPV6.*)=.$/# \1 is not set/' $config
  done
  ```
