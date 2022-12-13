#!/bin/bash
set -xeuo pipefail

[ $MIGHTY_SNITCH_AWS_ACCOUNT = $(libaws aws-account) ] || { echo wrong account; exit 1; }

cd $(dirname $0)

spot=${SPOT:-lowestPrice}
s3_cache_bucket=$MIGHTY_SNITCH_S3_BUCKET

alpine=alpine-3.17.0
key=relay
vpc=relay
 sg=relay
timeout_minutes=20

type=c6i.8xlarge
type_ami=c6i.large
arch=""

# type=c6g.8xlarge
# type_ami=c6g.medium
# arch="-arm64"

cache_version=$(cat APKBUILD |grep pkgver=|cut -d= -f2)

name=might-snitch-alpine${arch}

deploy() {
    rm -rf /tmp/abuild
    rm -rf /tmp/packages
    ami=$(libaws ec2-ami-latest $name)
    time (
        time libaws ec2-new \
             $name \
             -k $key \
             --sg $sg \
             --vpc $vpc \
             -a $ami \
             -g 32 \
             -t $type \
             -e \
             --spot $spot \
             --seconds-timeout $((60*$timeout_minutes))
        time libaws ec2-wait-ssh $name

        libaws ec2-rsync $(pwd) :/tmp $name

        time libaws ec2-ssh $name -c '
            sudo apk update
            sudo apk upgrade --ignore "linux*"
            # git config sets key name for abuild-keygen
            git config --global user.name "nathants"
            git config --global user.email "me@nathants.com"
            abuild-keygen -ain -b 4096
            sudo addgroup $(whoami) abuild
        '

        time libaws ec2-ssh $name -c "
            cd /
            mkdir -p /tmp/ccache
            if curl --no-progress-meter --fail '$(libaws s3-presign-get $s3_cache_bucket/cache/linux-edge-ccache-${cache_version}${arch}.tar)' > /tmp/ccache.tar; then
                tar xf /tmp/ccache.tar
            fi
            cd /tmp/alpine
            sudo ln -s /usr/bin/ccache /usr/local/bin/cc
            sudo ln -s /usr/bin/ccache /usr/local/bin/gcc
            abuild -r
            rm -vf /tmp/ccache.tar
            tar cf /tmp/ccache.tar /tmp/ccache/ /var/cache/distfiles/*
            curl --no-progress-meter --fail --upload-file /tmp/ccache.tar '$(libaws s3-presign-put $s3_cache_bucket/cache/linux-edge-ccache-${cache_version}${arch}.tar)'
        "
    )
    libaws ec2-rsync :.abuild/ /tmp/abuild $name
    libaws ec2-rsync :packages/ /tmp/packages $name
}

ami() {
    id=$(libaws ec2-new \
                $name \
                -k $key \
                --sg $sg \
                --vpc $vpc \
                -a $alpine \
                -g 8 \
                -t $type_ami \
                -e \
                --seconds-timeout 0)
    libaws ec2-wait-ssh $id
    libaws ec2-ssh $id -c '
    echo http://dl-cdn.alpinelinux.org/alpine/edge/main      | sudo tee    /etc/apk/repositories
    echo http://dl-cdn.alpinelinux.org/alpine/edge/community | sudo tee -a /etc/apk/repositories
    echo http://dl-cdn.alpinelinux.org/alpine/edge/testing   | sudo tee -a /etc/apk/repositories
    sudo apk update
    sudo apk upgrade -a
    sudo apk add \
      abuild \
      alpine-sdk \
      bash \
      bind-tools \
      coreutils \
      ccache \
      gcc \
      git \
      glances \
      go \
      libnetfilter_queue-dev \
      linux-edge \
      linux-edge-dev \
      linux-headers \
      musl-dev \
      ncurses-terminfo \
      nftables \
      python3 \
      rsync \
      shadow \
      util-linux
    curl --fail --no-progress-meter https://raw.githubusercontent.com/nathants/bootstraps/838c7f6776d7b1856cb6742d18aba8548bc26921/limits.sh | bash
    curl --fail --no-progress-meter https://raw.githubusercontent.com/nathants/bootstraps/838c7f6776d7b1856cb6742d18aba8548bc26921/sshd.sh   | bash
    sudo rm -fv /var/lib/cloud/.bootstrap-complete
    sudo rm -fv /var/lib/cloud/user-data
'
    libaws ec2-stop --wait $id
    libaws ec2-new-ami $id --wait
    libaws ec2-rm $id
}

libaws infra-ensure infra.yaml

libaws ec2-rm $name || true

if ! libaws ec2-ami-latest $name; then
    ami
fi

deploy

libaws ec2-rm $name || true
