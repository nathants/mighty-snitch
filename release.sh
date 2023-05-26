#!/bin/bash
(
    cd ~/snitch-binaries
    b2sum *
) > releases.b2sum
