#!/bin/sh

case "$1" in
    start)
        echo "Starting aesdsocket"
        start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket
        ;;
    stop)
        echo "Stopping aesdsocket"
        start-stop-daemon -K -n aesdsocket
        ;;
    *)
        echo "Usage erororrr!!!"
    exit 1
esac