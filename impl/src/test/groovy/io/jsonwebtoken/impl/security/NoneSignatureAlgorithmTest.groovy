/*
 * Copyright (C) 2018 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.SecureRequest
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.security.VerifySecureDigestRequest
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class NoneSignatureAlgorithmTest {

    private NoneSignatureAlgorithm alg

    @Before
    void setUp() {
        this.alg = new NoneSignatureAlgorithm()
    }

    @Test
    void testName() {
        assertEquals "none", alg.getId()
    }

    @Test(expected = SignatureException)
    void testDigest() {
        alg.digest((SecureRequest)null)
    }

    @Test(expected = SignatureException)
    void testVerify() {
        alg.verify((VerifySecureDigestRequest)null)
    }

    @Test
    void testHashCode() {
        assertEquals 'none'.hashCode(), alg.hashCode()
    }

    @Test
    void testEquals() {
        assertTrue alg == new NoneSignatureAlgorithm()
    }

    @Test
    void testIdentityEquals() {
        assertTrue alg == alg
    }

    @Test
    void testToString() {
        assertEquals alg.getId(), alg.toString()
    }
}
