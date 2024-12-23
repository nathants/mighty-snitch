gcc \
    -Ivendor/ \
    -Iutil/ \
    -O3 \
    -Wall \
    -flto \
    -o snitch \
    snitch.c \
    $(pkg-config libnetfilter_queue --cflags --libs)
