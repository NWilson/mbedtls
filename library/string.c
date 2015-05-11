/*
 *  Utility functions for managing string buffers
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

#include "polarssl/string.h"

#include <string.h>
#ifdef POLARSSL_HAVE_STDARG
#include <stdarg.h>
#endif

void string_builder_init( string_builder_context *ctx, char *buf,
                          size_t buf_size )
{
    ctx->buf = buf;
    ctx->remaining_space = buf_size;
    ctx->written = 0;
    if( ctx->remaining_space > 0 )
        *ctx->buf = '\0';
}

int string_builder_append( string_builder_context *ctx, const char *string,
                           int max_len )
{
    size_t len, write_size;

    if( max_len >= 0 )
    {
        for( len = 0; len < (size_t)max_len && string[len]; ++len )
            ;
    }
    else
    {
        len = strlen( string );
    }

    if( len + 1 <= ctx->remaining_space )
        write_size = len + 1;
    else
        write_size = ctx->remaining_space;

    if( write_size > 1 )
    {
        memcpy( ctx->buf, string, write_size - 1 );
        ctx->remaining_space -= write_size - 1;
        ctx->buf += write_size - 1;
    }
    ctx->written += len;
    if( ctx->remaining_space > 0 )
        *ctx->buf = '\0';
    return( len + 1 > write_size ? -1 : 0 );
}

#if defined POLARSSL_HAVE_STDARG && ! defined POLARSSL_PLATFORM_SNPRINTF_ALT

#undef polarssl_snprintf
#define polarssl_snprintf vsnprintf

void string_builder_printf( string_builder_context *ctx,
                            const char *format,
                            ... )
{
    va_list list;
    va_start(list, format);
    string_builder_printf_macro( ctx, ARG_LIST2( format, list ) );
    va_end(list);
}
#endif

int string_builder_append_unichar( string_builder_context *ctx, int code )
{
    char buf[4];
    int size = 0;

    if( code <= 0x7f )
    {
      buf[size++] = code;
    }
    else if( code <= 0x07ff )
    {
      buf[size++] = (0xc0 | (code >> 6));
      buf[size++] = (0x80 | (code & 0x3f));
    }
    else if( code <= 0xffff )
    {
      buf[size++] = (0xe0 | (code >> 12));
      buf[size++] = (0x80 | ((code >> 6) & 0x3f));
      buf[size++] = (0x80 | (code & 0x3f));
    }
    else if( code <= 0x10ffff )
    {
      buf[size++] = (0xf0 | (code >> 18));
      buf[size++] = (0x80 | ((code >> 12) & 0x3f));
      buf[size++] = (0x80 | ((code >> 6) & 0x3f));
      buf[size++] = (0x80 | (code & 0x3f));
    }
    else
    {
      return -1;
    }

    return( string_builder_append( ctx, buf, size ) );
}

int string_builder_append_hex( string_builder_context *ctx,
                               const unsigned char *buf, size_t size )
{
    size_t i, initial_space = ctx->remaining_space;

    for( i = 0; i < size; ++i )
    {
        string_builder_printf( ctx, ARG_LIST2( "%02X", buf[i] ) );
    }

    return( ctx->written >= initial_space ? -1 : 0 );
}
