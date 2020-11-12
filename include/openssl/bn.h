/*
 * Changes to OpenSSL version 1.1.1. copyright Amazon.com, Inc. All Rights Reserved.
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
#include <openssl/ossl_typ.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef HEADER_BN_H
#    define HEADER_BN_H
#    pragma once

/* Abstraction of the BIGNUM struct. */
struct bignum_st {
    bool is_initialized;
    unsigned long int *d; /* Pointer to an array of 'BN_BITS2' bit
                           * chunks. */
    int top;              /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax; /* Size of the d array. */
    int neg;  /* one if the number is negative */
    int flags;
};

BIGNUM *BN_new(void);
BIGNUM *BN_dup(const BIGNUM *from);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
void BN_clear_free(BIGNUM *a);
void BN_free(BIGNUM *a);

int BN_is_zero(BIGNUM *a);

#endif
