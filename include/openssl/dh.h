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

#include <cbmc_proof/nondet.h>
#include <openssl/bn.h>
#include <openssl/ffc.h>

#ifndef OPENSSL_DH_H
#    define OPENSSL_DH_H
#    pragma once

#    ifndef OPENSSL_NO_DEPRECATED_3_0
#        define HEADER_DH_H
#    endif

/*
 * The structs dh_st and dh_method have been cut down to contain
 * only the parts relevant to the s2n_pkcs3_to_dh_params proof.
 */

struct dh_st {
    /*
     * This first argument is used to pick up errors when a DH is passed
     * instead of a EVP_PKEY
     */
    int pad;
    int version;
    FFC_PARAMS params;
    /* max generated private key length (can be less than len(q)) */
    int32_t length;
    BIGNUM *pub_key;  /* g^x % p */
    BIGNUM *priv_key; /* x */
    int flags;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;

    /* Provider data */
    size_t dirty_cnt; /* If any key material changes, increment this */
};

struct dh_method {
    char *name;
};

DH *DH_new(void);
bool openssl_DH_is_valid(const DH *dh);
void DH_free(DH *dh);
int DH_size(const DH *dh);
DH *d2i_DHparams(DH **a, unsigned char **pp, long length);
int DH_check(DH *dh, int *codes);
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
int DH_generate_key(DH *dh);
DH *DHparams_dup(const DH *dh);

#endif
