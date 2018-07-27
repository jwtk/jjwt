/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test

import javax.crypto.SecretKey

import static org.junit.Assert.assertEquals

class MacProviderTest {

    private void testHmac(SignatureAlgorithm alg) {
        testHmac(alg, MacProvider.generateKey(alg))
    }

    private void testHmac(SignatureAlgorithm alg, SecretKey key) {
        assertEquals alg.jcaName, key.algorithm
        assertEquals alg.digestLength / 8 as int, key.encoded.length
    }

    @Test
    void testDefault() {
        testHmac(SignatureAlgorithm.HS512, MacProvider.generateKey())
    }

    @Test
    void testHS256() {
        testHmac(SignatureAlgorithm.HS256)
    }

    @Test
    void testHS384() {
        testHmac(SignatureAlgorithm.HS384)
    }

    @Test
    void testHS512() {
        testHmac(SignatureAlgorithm.HS512)
    }
}
