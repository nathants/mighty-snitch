upstream source: https://gitlab.com/postmarketOS/pmaports/-/tree/master/device/community/linux-postmarketos-qcom-sdm845

when updating kernel configs, take upstream, and then ensure the following:

- `CONFIG_SECURITY_NETWORK=y`

- `CONFIG_LSM="snitch"`

- `CONFIG_SNITCH=y`

- `CONFIG_NETFILTER_NETLINK_QUEUE=m`

- `CONFIG_NFT_QUEUE=m`

- `CONFIG_HIDRAW=y`

- `CONFIG_USB_HIDDEV=y`

- disable ipv6:
  ```bash
  ls config-* | while read config; do
      sed -i -r 's/^(CONFIG_.*IPV6.*)=.$/# \1 is not set/' $config
  done
  ```
