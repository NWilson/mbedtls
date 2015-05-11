/*
 *  X.509 Certificate Signing Request (CSR) parsing
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
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_X509_CSR_PARSE_C)

#include "polarssl/x509_csr.h"
#include "polarssl/oid.h"

#include <string.h>

#if defined(POLARSSL_PEM_PARSE_C)
#include "polarssl/pem.h"
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define polarssl_free       free
#define polarssl_malloc     malloc
#define polarssl_snprintf   snprintf
#endif

#if defined(POLARSSL_FS_IO) || defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif

/* Implementation that should never be optimized out by the compiler */
static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 *  Version  ::=  INTEGER  {  v1(0)  }
 */
static int x509_csr_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;

    if( ( ret = asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( POLARSSL_ERR_X509_INVALID_VERSION + ret );
    }

    return( 0 );
}

/*
 * Parse a CSR in DER format
 */
int x509_csr_parse_der( x509_csr *csr,
                        const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;
    x509_buf sig_params;

    memset( &sig_params, 0, sizeof( x509_buf ) );

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL )
        return( POLARSSL_ERR_X509_BAD_INPUT_DATA );

    x509_csr_init( csr );

    /*
     * first copy the raw DER data
     */
    p = polarssl_malloc( len = buflen );

    if( p == NULL )
        return( POLARSSL_ERR_X509_MALLOC_FAILED );

    memcpy( p, buf, buflen );

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

    /*
     *  CertificationRequest ::= SEQUENCE {
     *       certificationRequestInfo CertificationRequestInfo,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signature          BIT STRING
     *  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if( ( ret = x509_csr_get_version( &p, end, &csr->version ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    csr->version++;

    if( csr->version != 1 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_UNKNOWN_VERSION );
    }

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &csr->subject ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if( ( ret = pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    /*
     *  attributes    [0] Attributes
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }
    // TODO Parse Attributes / extension requests

    p += len;

    end = csr->raw.p + csr->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if( ( ret = x509_get_alg( &p, end, &csr->sig_oid, &sig_params ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = x509_get_sig_alg( &csr->sig_oid, &sig_params,
                                  &csr->sig_md, &csr->sig_pk,
                                  &csr->sig_opts ) ) != 0 )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        x509_csr_free( csr );
        return( ret );
    }

    if( p != end )
    {
        x509_csr_free( csr );
        return( POLARSSL_ERR_X509_INVALID_FORMAT +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
 * Parse a CSR, allowing for PEM or raw DER encoding
 */
int x509_csr_parse( x509_csr *csr, const unsigned char *buf, size_t buflen )
{
    int ret;
#if defined(POLARSSL_PEM_PARSE_C)
    size_t use_len;
    pem_context pem;
#endif

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL )
        return( POLARSSL_ERR_X509_BAD_INPUT_DATA );

#if defined(POLARSSL_PEM_PARSE_C)
    pem_init( &pem );
    ret = pem_read_buffer( &pem,
                           "-----BEGIN CERTIFICATE REQUEST-----",
                           "-----END CERTIFICATE REQUEST-----",
                           buf, NULL, 0, &use_len );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded, parse the result
         */
        if( ( ret = x509_csr_parse_der( csr, pem.buf, pem.buflen ) ) != 0 )
            return( ret );

        pem_free( &pem );
        return( 0 );
    }
    else if( ret != POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        pem_free( &pem );
        return( ret );
    }
    else
#endif /* POLARSSL_PEM_PARSE_C */
    return( x509_csr_parse_der( csr, buf, buflen ) );
}

#if defined(POLARSSL_FS_IO)
/*
 * Load a CSR into the structure
 */
int x509_csr_parse_file( x509_csr *csr, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = x509_csr_parse( csr, buf, n );

    polarssl_zeroize( buf, n + 1 );
    polarssl_free( buf );

    return( ret );
}
#endif /* POLARSSL_FS_IO */

#define POLARSSL_ERR_DEBUG_BUF_TOO_SMALL    -2

#define CHECK_AND_SKIP( ret, builder ) \
    if( ret < 0 ) \
        return( ret ); \
    builder.buf += ret; \
    builder.remaining_space -= ret; \
    builder.written += ret;

#define BEFORE_COLON    14
#define BC              "14"
/*
 * Return an informational string about the CSR.
 */
int x509_csr_info( char *buf, size_t size, const char *prefix,
                   const x509_csr *csr )
{
    int ret;
    char key_size_str[BEFORE_COLON];
    string_builder_context builder;

    string_builder_init( &builder, buf, size );

    string_builder_printf( &builder, ARG_LIST3( "%sCSR version   : %d",
                           prefix, csr->version ) );

    string_builder_printf( &builder, ARG_LIST2( "\n%ssubject name  : ",
                           prefix ) );

    ret = x509_dn_gets( builder.buf, builder.remaining_space, &csr->subject );
    CHECK_AND_SKIP( ret, builder );

    string_builder_printf( &builder, ARG_LIST2( "\n%ssigned using  : ",
                           prefix ) );

     x509_sig_alg_gets( &builder, &csr->sig_oid, csr->sig_pk, csr->sig_md,
                        csr->sig_opts );

    if( ( ret = x509_key_size_helper( key_size_str, BEFORE_COLON,
                                      pk_get_name( &csr->pk ) ) ) != 0 )
    {
        return( ret );
    }

    string_builder_printf( &builder, ARG_LIST4( "\n%s%-" BC "s: %d bits\n",
                           prefix, key_size_str,
                           (int) pk_get_size( &csr->pk ) ) );

    /* x509_csr_info returns -2 for overflows, but this is undocumented */
    if( builder.written >= size )
        return( POLARSSL_ERR_DEBUG_BUF_TOO_SMALL );
    return( (int) builder.written );
}

/*
 * Initialize a CSR
 */
void x509_csr_init( x509_csr *csr )
{
    memset( csr, 0, sizeof(x509_csr) );
}

/*
 * Unallocate all CSR data
 */
void x509_csr_free( x509_csr *csr )
{
    x509_name *name_cur;
    x509_name *name_prv;

    if( csr == NULL )
        return;

    pk_free( &csr->pk );

#if defined(POLARSSL_X509_RSASSA_PSS_SUPPORT)
    polarssl_free( csr->sig_opts );
#endif

    name_cur = csr->subject.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        polarssl_zeroize( name_prv, sizeof( x509_name ) );
        polarssl_free( name_prv );
    }

    if( csr->raw.p != NULL )
    {
        polarssl_zeroize( csr->raw.p, csr->raw.len );
        polarssl_free( csr->raw.p );
    }

    polarssl_zeroize( csr, sizeof( x509_csr ) );
}

#endif /* POLARSSL_X509_CSR_PARSE_C */
