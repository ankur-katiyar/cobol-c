#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) int cfunc(char *st, int *c)
{
    strncpy(st, "From C", 20);
    *c = 99;
    return 10;
}

#ifdef __cplusplus
}
#endif
