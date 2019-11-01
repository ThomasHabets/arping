#include<libnet.h>
#include"config.h"

#define UNUSED(x) (void)(x)
int mock_libnet_null_ok = 1;
int mock_libnet_lo_ok = 1;

void
libnet_destroy(libnet_t* l)
{
        free(l);
}

#if HAVE_LIBNET_INIT_CONST
#define LIBNET_INIT_CONST const
#else
#define LIBNET_INIT_CONST
#endif

libnet_t*
libnet_init(int injection_type, LIBNET_INIT_CONST char *device, char *err_buf)
{
        UNUSED(injection_type);
        UNUSED(err_buf);
        if (device == NULL) {
                if (mock_libnet_null_ok) {
                        return malloc(sizeof(libnet_t));
                }
                return NULL;
        }
        if (!strcmp(device, "bad")) {
                return NULL;
        }
        if (!strcmp(device, "good")) {
                return malloc(sizeof(libnet_t));
        }
        if (mock_libnet_lo_ok && !strcmp(device, "lo")) {
                return malloc(sizeof(libnet_t));
        }
        return NULL;
}

/* ---- Emacs Variables ----
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vim: ts=8 sw=8
 */
