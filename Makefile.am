AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

libgatt_la_CFLAGS = $(WARNING_CFLAGS) $(MISC_CFLAGS) @GLIB_CFLAGS@
libgatt_la_LDFLAGS = @GLIB_LIBS@

lib_LTLIBRARIES = libgatt.la
libgatt_la_SOURCES = src/att.c src/gatt.c src/gattrib.c src/btio.c lib/uuid.c src/hci.c src/sdp.c src/bluetooth.c src/shared/crypto.c src/shared/queue.c src/log.c src/shared/att.c src/shared/util.c src/shared/timeout-glib.c src/shared/io-glib.c

pkginclude_HEADERS = src/att.h src/btio.h src/gatt.h src/gattrib.h src/bluetooth.h
