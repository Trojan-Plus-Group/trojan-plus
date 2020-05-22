#ifndef LWIP_CUSTOM_CC_H
#define LWIP_CUSTOM_CC_H

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#include <byteorder.h>

#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END
#if defined(__GNUC__) && defined(__MINGW32__)
// Workaround https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52991
#define PACK_STRUCT_STRUCT __attribute__((packed)) __attribute__((gcc_struct))
#else
#define PACK_STRUCT_STRUCT __attribute__((packed))
#endif

#define LWIP_PLATFORM_DIAG(x) { fprintf(stdout, "%s: lwip diag failure: %s\n", __FUNCTION__, (x)); }
#define LWIP_PLATFORM_ASSERT(x) { fprintf(stderr, "%s: lwip assertion failure: %s\n", __FUNCTION__, (x)); abort(); }

#define lwip_htons(x) hton16(x)
#define lwip_htonl(x) hton32(x)

#define LWIP_RAND() ( \
    (((uint32_t)(rand() & 0xFF)) << 24) | \
    (((uint32_t)(rand() & 0xFF)) << 16) | \
    (((uint32_t)(rand() & 0xFF)) << 8) | \
    (((uint32_t)(rand() & 0xFF)) << 0) \
)

// for BYTE_ORDER
#if defined(BADVPN_USE_WINAPI) && !defined(_MSC_VER)
    #include <sys/param.h>
#elif defined(BADVPN_LINUX)
    #include <endian.h>
#elif defined(BADVPN_FREEBSD)
    #include <machine/endian.h>
#else
    #define LITTLE_ENDIAN 1234
    #define BIG_ENDIAN 4321
    #if defined(BADVPN_LITTLE_ENDIAN)
        #define BYTE_ORDER LITTLE_ENDIAN
    #else
        #define BYTE_ORDER BIG_ENDIAN
    #endif
#endif


#endif
