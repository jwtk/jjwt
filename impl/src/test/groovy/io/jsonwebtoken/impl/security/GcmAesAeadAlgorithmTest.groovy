/*
 * Copyright (C) 2020 jsonwebtoken.io
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

import io.jsonwebtoken.Jwts
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.fail

/**
 * @since JJWT_RELEASE_VERSION
 */
class GcmAesAeadAlgorithmTest {

    final byte[] K =
            [0xb1, 0xa1, 0xf4, 0x80, 0x54, 0x8f, 0xe1, 0x73, 0x3f, 0xb4, 0x3, 0xff, 0x6b, 0x9a, 0xd4, 0xf6,
             0x8a, 0x7, 0x6e, 0x5b, 0x70, 0x2e, 0x22, 0x69, 0x2f, 0x82, 0xcb, 0x2e, 0x7a, 0xea, 0x40, 0xfc] as byte[]
    final SecretKey KEY = new SecretKeySpec(K, "AES")

    final byte[] P = "The true sign of intelligence is not knowledge but imagination.".getBytes("UTF-8")

    final byte[] IV = [0xe3, 0xc5, 0x75, 0xfc, 0x2, 0xdb, 0xe9, 0x44, 0xb4, 0xe1, 0x4d, 0xdb] as byte[]

    final byte[] AAD =
            [0x65, 0x79, 0x4a, 0x68, 0x62, 0x47, 0x63, 0x69, 0x4f, 0x69, 0x4a, 0x53, 0x55, 0x30, 0x45, 0x74,
             0x54, 0x30, 0x46, 0x46, 0x55, 0x43, 0x49, 0x73, 0x49, 0x6d, 0x56, 0x75, 0x59, 0x79, 0x49, 0x36,
             0x49, 0x6b, 0x45, 0x79, 0x4e, 0x54, 0x5a, 0x48, 0x51, 0x30, 0x30, 0x69, 0x66, 0x51] as byte[]

    final byte[] E =
            [0xe5, 0xec, 0xa6, 0xf1, 0x35, 0xbf, 0x73, 0xc4, 0xae, 0x2b, 0x49, 0x6d, 0x27, 0x7a, 0xe9, 0x60,
             0x8c, 0xce, 0x78, 0x34, 0x33, 0xed, 0x30, 0xb, 0xbe, 0xdb, 0xba, 0x50, 0x6f, 0x68, 0x32, 0x8e,
             0x2f, 0xa7, 0x3b, 0x3d, 0xb5, 0x7f, 0xc4, 0x15, 0x28, 0x52, 0xf2, 0x20, 0x7b, 0x8f, 0xa8, 0xe2,
             0x49, 0xd8, 0xb0, 0x90, 0x8a, 0xf7, 0x6a, 0x3c, 0x10, 0xcd, 0xa0, 0x6d, 0x40, 0x3f, 0xc0] as byte[]

    final byte[] T =
            [0x5c, 0x50, 0x68, 0x31, 0x85, 0x19, 0xa1, 0xd7, 0xad, 0x65, 0xdb, 0xd3, 0x88, 0x5b, 0xd2, 0x91] as byte[]

    /**
     * Test that reflects https://tools.ietf.org/html/rfc7516#appendix-A.1
     */
    @Test
    void testEncryptionAndDecryption() {

        def alg = Jwts.ENC.A256GCM

        def req = new DefaultAeadRequest(P, null, null, KEY, AAD, IV)

        def result = alg.encrypt(req)

        byte[] ciphertext = result.getPayload()
        byte[] tag = result.getDigest()
        byte[] iv = result.getInitializationVector()

        assertArrayEquals E, ciphertext
        assertArrayEquals T, tag
        assertArrayEquals IV, iv //shouldn't have been altered

        // now test decryption:
        def dreq = new DefaultAeadResult(null, null, ciphertext, KEY, AAD, tag, iv)
        byte[] decryptionResult = alg.decrypt(dreq).getPayload()
        assertArrayEquals(P, decryptionResult)
    }

    @Test
    void testInstantiationWithInvalidKeyLength() {
        try {
            new GcmAesAeadAlgorithm(5)
            fail()
        } catch (IllegalArgumentException ignored) {
        }
    }
}
