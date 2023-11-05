#!/bin/bash
set -xeou pipefail

cd $(dirname $0)

rm -f snitch

gcc \
    -Ivendor/ \
    -Iutil/ \
    -O3 \
    -Wall \
    -flto \
    -o snitch \
    snitch.c \
    $(pkg-config libnetfilter_queue --cflags --libs)

echo start snitch

sudo kill $(ps -ef | grep '\./snitch' | awk '{print $2}') || true
sleep 1

sudo rm -f /tmp/snitch*

# wayland postmarketos needs to do this to allow root gui access
if which foot &>/dev/null; then
    xhost +si:localuser:root
fi

if [ "${COLOR:-y}" = n ]; then
    sudo -E stdbuf -o0 ./snitch
else
    sudo -E stdbuf -o0 ./snitch 2>&1\
        | tee ${SNITCH_LOG:-/tmp/snitch.log} \
        | color \
              allow:green \
              deny:red \
              dns:white \
              add-rule:white \
              delete-rule:white \
              update-rule:white \
              expire-rule:white \
              load-rule:white \
              1:cyan \
              2:magenta \
              3:yellow \
              4:blue \
              5:white \
        | count-last
fi
