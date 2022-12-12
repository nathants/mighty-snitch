#!/bin/bash
set -xeou pipefail

[ $MIGHTY_SNITCH_AWS_ACCOUNT = $(libaws aws-account) ] || { echo wrong account; exit 1; }

cd $(dirname $0)

spot=${SPOT:-lowestPrice}

name=might-snitch-alpine-sdm845
alpine=alpine-3.16.2
type=c6i.8xlarge
key=relay
vpc=relay
 sg=relay
timeout_minutes=30

channel=edge
vendor=oneplus
device=fajita
user=nobody
interface=phosh
hostname=6t

libaws infra-ensure infra.yaml

libaws ec2-rm $name || true

id=$(libaws ec2-new \
            -e \
            -k $key \
            --sg $sg \
            --vpc $vpc \
            --spot $spot \
            -t $type \
            -a $alpine \
            --gigs 32 \
            --seconds-timeout $((60*${timeout_minutes})) \
            $name)

libaws ec2-wait-ssh $id

libaws ec2-ssh $id -c "
echo http://dl-cdn.alpinelinux.org/alpine/edge/main      | sudo tee    /etc/apk/repositories
echo http://dl-cdn.alpinelinux.org/alpine/edge/community | sudo tee -a /etc/apk/repositories
echo http://dl-cdn.alpinelinux.org/alpine/edge/testing   | sudo tee -a /etc/apk/repositories
sudo apk update
sudo apk upgrade -a
sudo apk add openssl git procps python3 rsync
python3 -m ensurepip
python3 -m pip install pmbootstrap
export PATH=\$PATH:~/.local/bin
(
    echo ~/pmos
    echo $channel
    echo $vendor
    echo $device
    echo y # non-free binaries
    echo $user
    echo $interface
    echo n # change options defaults
    echo none # extra packages
    echo en_US.UTF-8
    echo $hostname
    echo y # build outdated packages
) | pmbootstrap init
pmbootstrap update
"

libaws ec2-scp config-postmarketos-qcom-sdm845.aarch64 :/tmp $id
libaws ec2-scp APKBUILD :/tmp $id
libaws ec2-scp 0001-snitch.patch :/tmp $id

libaws ec2-ssh $id -c '
export PATH=$PATH:~/.local/bin
pmbootstrap kconfig edit postmarketos-qcom-sdm845 &> edit.log &
while true; do
    if cat edit.log |grep " Arrow keys navigate the menu." &>/dev/null; then
        echo done
        break
    fi
    echo wait for kconfig bootstrap
    sleep 1
done
kill %1
paths="
  /home/alpine/pmos/chroot_native/home/pmos/build/
  /home/alpine/pmos/chroot_native/mnt/pmbootstrap-git/pmaports/device/community/linux-postmarketos-qcom-sdm845/
  /home/alpine/pmos/cache_git/pmaports/device/community/linux-postmarketos-qcom-sdm845/
"
for path in $paths; do
    sudo cp -fv /tmp/config-postmarketos-qcom-sdm845.aarch64 $path
    sudo cp -fv /tmp/APKBUILD $path
    sudo cp -fv /tmp/0001-snitch.patch $path
done
# pmbootstrap kconfig check postmarketos-qcom-sdm845 # no check because we are making weird changes to kconfig
if ! pmbootstrap build --force linux-postmarketos-qcom-sdm845; then
    pmbootstrap log &
    sleep 5
    exit 1
fi
'

apk=$(libaws ec2-ssh $id -c "ls ~/pmos/packages/edge/aarch64/linux-postmarketos-qcom-sdm845-*.apk")
pub=$(libaws ec2-ssh $id -c "ls ~/pmos/config_apk_keys/pmos@local-*.rsa.pub")

rm -f /tmp/*.apk
rm -f /tmp/*.pub

libaws ec2-scp ":$apk" /tmp $id
libaws ec2-scp ":$pub" /tmp $id

libaws ec2-rm $id
