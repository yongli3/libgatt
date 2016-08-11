#include "utils.h"
#include "log.h"

int main() {
    __btd_log_init("*", 0);
	gatt_connect("foo", "bar", "baz", "dunno", 0, 0, NULL, NULL);

    __btd_log_cleanup();
}
