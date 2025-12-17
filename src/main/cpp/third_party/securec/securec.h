/**
 * securec.h - Secure C Library Compatibility Layer
 * 
 * This header provides compatibility implementations for the secure C functions
 * used by HDC core code. On HarmonyOS NDK, we map these to standard C functions
 * or provide simple implementations.
 */
#ifndef SECUREC_H
#define SECUREC_H

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#ifndef EOK
#define EOK 0
#endif

#ifndef EINVAL_AND_RESET
#define EINVAL_AND_RESET EINVAL
#endif

// Type definitions
typedef int errno_t;

// memset_s - Secure memset
static inline errno_t memset_s(void *dest, size_t destMax, int c, size_t count) {
    if (dest == NULL || destMax == 0 || count > destMax) {
        return EINVAL;
    }
    memset(dest, c, count);
    return EOK;
}

// memcpy_s - Secure memcpy
static inline errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count) {
    if (dest == NULL || src == NULL || destMax == 0 || count > destMax) {
        return EINVAL;
    }
    memcpy(dest, src, count);
    return EOK;
}

// memmove_s - Secure memmove
static inline errno_t memmove_s(void *dest, size_t destMax, const void *src, size_t count) {
    if (dest == NULL || src == NULL || destMax == 0 || count > destMax) {
        return EINVAL;
    }
    memmove(dest, src, count);
    return EOK;
}

// strcpy_s - Secure strcpy
static inline errno_t strcpy_s(char *dest, size_t destMax, const char *src) {
    if (dest == NULL || src == NULL || destMax == 0) {
        return EINVAL;
    }
    size_t srcLen = strlen(src);
    if (srcLen >= destMax) {
        dest[0] = '\0';
        return EINVAL;
    }
    strcpy(dest, src);
    return EOK;
}

// strncpy_s - Secure strncpy
static inline errno_t strncpy_s(char *dest, size_t destMax, const char *src, size_t count) {
    if (dest == NULL || src == NULL || destMax == 0) {
        return EINVAL;
    }
    size_t copyLen = count;
    size_t srcLen = strlen(src);
    if (copyLen > srcLen) {
        copyLen = srcLen;
    }
    if (copyLen >= destMax) {
        dest[0] = '\0';
        return EINVAL;
    }
    strncpy(dest, src, copyLen);
    dest[copyLen] = '\0';
    return EOK;
}

// strcat_s - Secure strcat
static inline errno_t strcat_s(char *dest, size_t destMax, const char *src) {
    if (dest == NULL || src == NULL || destMax == 0) {
        return EINVAL;
    }
    size_t destLen = strlen(dest);
    size_t srcLen = strlen(src);
    if (destLen + srcLen >= destMax) {
        return EINVAL;
    }
    strcat(dest, src);
    return EOK;
}

// strncat_s - Secure strncat
static inline errno_t strncat_s(char *dest, size_t destMax, const char *src, size_t count) {
    if (dest == NULL || src == NULL || destMax == 0) {
        return EINVAL;
    }
    size_t destLen = strlen(dest);
    size_t srcLen = strlen(src);
    size_t copyLen = (count < srcLen) ? count : srcLen;
    if (destLen + copyLen >= destMax) {
        return EINVAL;
    }
    strncat(dest, src, copyLen);
    return EOK;
}

// sprintf_s - Secure sprintf
static inline int sprintf_s(char *dest, size_t destMax, const char *format, ...) {
    if (dest == NULL || format == NULL || destMax == 0) {
        return -1;
    }
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(dest, destMax, format, args);
    va_end(args);
    if (ret < 0 || (size_t)ret >= destMax) {
        dest[0] = '\0';
        return -1;
    }
    return ret;
}

// snprintf_s - Secure snprintf
static inline int snprintf_s(char *dest, size_t destMax, size_t count, const char *format, ...) {
    if (dest == NULL || format == NULL || destMax == 0) {
        return -1;
    }
    size_t maxLen = (count < destMax) ? count : destMax - 1;
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(dest, maxLen + 1, format, args);
    va_end(args);
    if (ret < 0) {
        dest[0] = '\0';
        return -1;
    }
    return ret;
}

// vsprintf_s - Secure vsprintf
static inline int vsprintf_s(char *dest, size_t destMax, const char *format, va_list args) {
    if (dest == NULL || format == NULL || destMax == 0) {
        return -1;
    }
    int ret = vsnprintf(dest, destMax, format, args);
    if (ret < 0 || (size_t)ret >= destMax) {
        dest[0] = '\0';
        return -1;
    }
    return ret;
}

// vsnprintf_s - Secure vsnprintf
static inline int vsnprintf_s(char *dest, size_t destMax, size_t count, const char *format, va_list args) {
    if (dest == NULL || format == NULL || destMax == 0) {
        return -1;
    }
    size_t maxLen = (count < destMax) ? count : destMax - 1;
    int ret = vsnprintf(dest, maxLen + 1, format, args);
    if (ret < 0) {
        dest[0] = '\0';
        return -1;
    }
    return ret;
}

// scanf_s - Secure scanf (simplified, just use scanf)
#define scanf_s scanf

// sscanf_s - Secure sscanf (simplified, just use sscanf)
#define sscanf_s sscanf

// fscanf_s - Secure fscanf (simplified, just use fscanf)
#define fscanf_s fscanf

// gets_s - Secure gets
static inline char* gets_s(char *dest, size_t destMax) {
    if (dest == NULL || destMax == 0) {
        return NULL;
    }
    return fgets(dest, (int)destMax, stdin);
}

// strtok_s - Secure strtok
static inline char* strtok_s(char *str, const char *delim, char **context) {
    if (delim == NULL || context == NULL) {
        return NULL;
    }
    return strtok_r(str, delim, context);
}

#ifdef __cplusplus
}
#endif

#endif // SECUREC_H
