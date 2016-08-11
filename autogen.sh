#!/bin/sh

rm -f config.cache

if [ -d m4 ]; then
        echo "Looking in m4 directory for macros."
        aclocal -I m4
else
        echo "Looking in current directory for macros."
        aclocal -I .
        fi

autoconf
autoheader
automake -a
exit

