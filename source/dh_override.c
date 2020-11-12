/*
 * Changes to OpenSSL version 1.1.1.
 * Copyright Amazon.com, Inc. All Rights Reserved.
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <openssl/dh.h>
#include <openssl/ossl_typ.h>

bool openssl_DH_is_valid(const DH *dh) {
    return __CPROVER_w_ok(dh, sizeof(*dh));
}

int DH_size(const DH *dh) {
    /**
     * Both dh and dh->p must not be NULL.
     * Per https://www.openssl.org/docs/man1.1.0/man3/DH_size.html.
     */
    assert(openssl_DH_is_valid(dh));
    assert(dh->p != NULL);
    return nondet_int();
}

void DH_free(DH *dh) {
    assert(dh == NULL || openssl_DH_is_valid(dh));
    if (dh != NULL) free(dh);
    return;
}

/* Returns a dummy DH that can't be dereferenced. */
DH *d2i_DHparams(DH **a, const unsigned char **pp, long length) {
    assert(pp != NULL);
    DH *dummy_dh = malloc(sizeof(*dummy_dh));
    if (dummy_dh != NULL) {
        dummy_dh->pub_key  = malloc(sizeof(*(dummy_dh->pub_key)));
        dummy_dh->priv_key = malloc(sizeof(*(dummy_dh->priv_key)));
        dummy_dh->p        = malloc(sizeof(*(dummy_dh->p)));
        dummy_dh->g        = malloc(sizeof(*(dummy_dh->g)));
        if (a != NULL) *a = dummy_dh;
    }
    if (nondet_bool() && *pp != NULL) {
        *pp = *pp + length;
    }
    return dummy_dh;
}

int DH_check(DH *dh, int *codes) {
    assert(openssl_DH_is_valid(dh));
    assert(codes != NULL);
    *codes = nondet_int();
    return (int)nondet_bool();
}

/**
 * The p, q and g parameters can be obtained by calling DH_get0_pqg().
 * If the parameters have not yet been set then
 * *p, *q and *g will be set to NULL.
 * Per https://www.openssl.org/docs/man1.1.0/man3/DH_get0_pqg.html.
 */
void DH_get0_pqg(const DH *dh, BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
    assert(openssl_DH_is_valid(dh));
    if (p != NULL) {
        if (dh->p != NULL) {
            *p = dh->p;
        } else {
            *p = NULL;
        }
    }
    if (q != NULL) {
        if (dh->q != NULL) {
            *q = dh->q;
        } else {
            *q = NULL;
        }
    }
    if (g != NULL) {
        if (dh->g != NULL) {
            *g = dh->g;
        } else {
            *g = NULL;
        }
    }
}
