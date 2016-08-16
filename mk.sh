#./autogen.sh
./bootstrap
CFLAGS="-g" CC="ccache gcc" ./configure --prefix=/usr


