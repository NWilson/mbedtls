/**
 * \file string.h
 *
 * \brief Utility functions for managing string buffers
 *
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_STRING_H
#define POLARSSL_STRING_H

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#endif

#if defined(_MSC_VER) && !defined  snprintf && !defined(EFIX64) && \
    !defined(EFI32)
#define  snprintf  _snprintf
#define  vsnprintf _vsnprintf
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          String builder context structure
 */
typedef struct _string_builder_context
{
  char *buf;
  size_t remaining_space, written;
}
string_builder_context;

/**
 * \brief          Initialize a string builder context
 *
 *                 The buffer will have a terminating nul added immediately.
 *
 * \param ctx      String builder context to be initialized
 * \param buf      Buffer into which the string will be written
 * \param buf_size Size in bytes of the buffer
 *
 * \note           If the buffer has zero size, then it will not be
 *                 nul-terminated.
 */
void string_builder_init( string_builder_context *ctx,
                          char *buf,
                          size_t buf_size );

/**
 * \brief          Write a string into the context
 *
 *                 If the string is nul-terminated, pass -1 for the max_len
 *                 parameter; otherwise, for strings stored as data-with-length,
 *                 pass the length as max_len.  Note that embedded nuls cannot
 *                 be printed (if there is a null in the data before max_len is
 *                 reached, the rest of the string will not be copied).
 *
 * \param ctx      String builder context to use
 * \param string   The string to write
 * \param max_len  The length of the string, excluding the terminating nul, or
 *                 -1 to copy until nul is reached
 *
 * \return         0 on success, or -1 if the string was truncated
 */
int string_builder_append( string_builder_context *ctx,
                           const char *string,
                           int max_len );

#define string_builder_printf_macro( ctx, args )                            \
    do {                                                                    \
        size_t ret;                                                         \
        ret = polarssl_snprintf( (ctx)->buf, (ctx)->remaining_space, args); \
        /* Visual Studio and old Unix/Linux snprintf() return -1 for */     \
        /* overflow, so we just guess at the output size. */                \
        if( ret < 0 )                                                       \
            ret = ((ctx)->remaining_space * 2) + 20;                        \
        (ctx)->written += ret;                                              \
        if( (ctx)->remaining_space == 0 ) {}                                \
        else if( ret >= (ctx)->remaining_space )                            \
        {                                                                   \
            (ctx)->buf += (ctx)->remaining_space - 1;                       \
            (ctx)->remaining_space = 1;                                     \
        }                                                                   \
        else                                                                \
        {                                                                   \
            (ctx)->buf += ret;                                              \
            (ctx)->remaining_space -= ret;                                  \
        }                                                                   \
        if( (ctx)->remaining_space > 0 )                                    \
            *(ctx)->buf = '\0';                                             \
    } while(0)

/**
 * \brief          Write a formatted string into the context
 *
 *                 This is a safe wrapper around polarssl_snprintf() which makes
 *                 up for deficiencies in the platform's snprintf(), in
 *                 particular by explicitly nul-terminating the output, and
 *                 handling old implementations which return -1 on overflow.
 *
 *                 This wrapper is usually defined as a wrapper function which
 *                 forwards its arguments to the platform's vsnprintf(), but we
 *                 also allow for compilers which don't support stdarg.h and for
 *                 custom polarssl_snprintf() functions, by providing a macro
 *                 version.  For compatibility with both, the ARG_LISTn() macros
 *                 must be used to construct the printf arguments.
 *
 * \param ctx      String builder context to use
 * \param args     A list of arguments to pass to snprintf().  To construct the
 *                 list, use the ARG_LISTn() macros below.
 */
#if defined POLARSSL_HAVE_STDARG && ! defined POLARSSL_PLATFORM_SNPRINTF_ALT
void string_builder_printf( string_builder_context *ctx,
                            const char *format,
                            ... );
#else
#define string_builder_printf( ctx, args ) \
        string_builder_printf_macro( ctx, args )
#endif

#define ARG_LIST2(arg1, arg2) arg1, arg2
#define ARG_LIST3(arg1, arg2, arg3) arg1, arg2, arg3
#define ARG_LIST4(arg1, arg2, arg3, arg4) arg1, arg2, arg3, arg4
#define ARG_LIST5(arg1, arg2, arg3, arg4, arg5) arg1, arg2, arg3, arg4, arg5
#define ARG_LIST6(arg1, arg2, arg3, arg4, arg5, arg6) \
  arg1, arg2, arg3, arg4, arg5, arg6
#define ARG_LIST7(arg1, arg2, arg3, arg4, arg5, arg6, arg7) \
  arg1, arg2, arg3, arg4, arg5, arg6, arg7
#define ARG_LIST8(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8) \
  arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8

/**
 * \brief          Write a unicode character into the context as UTF-8
 *
 * \param ctx      String builder context to use
 * \param code     The codepoint to write
 *
 * \return         0 on success, or -1 if codepoint is out of range or was
 *                 truncated
 */
int string_builder_append_unichar( string_builder_context *ctx,
                                   int code );

/**
 * \brief          Write an octet string as hexadecimal characters
 *
 * \param ctx      String builder context to use
 * \param buf      The data to write
 * \param size     The length of the data
 *
 * \return         0 on success, or -1 if hex characters were truncated
 */
int string_builder_append_hex( string_builder_context *ctx,
                               const unsigned char *buf,
                               size_t size );

#ifdef __cplusplus
}
#endif

#endif /* string.h */
