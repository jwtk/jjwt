/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.JweHeader
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.impl.DefaultMutableJweHeader
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.lang.Arrays
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SecretKeyBuilder
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

import static org.junit.Assert.*

class AesGcmKeyAlgorithmTest {

    /**
     * This tests asserts that our AeadAlgorithm implementation and the JCA 'AES/GCM/NoPadding' wrap algorithm
     * produce the exact same values.  This should be the case when the transformation is identical, even though
     * one uses Cipher.WRAP_MODE and the other uses a raw plaintext byte array.
     */
    @Test
    void testAesWrapProducesSameResultAsAesAeadEncryptionAlgorithm() {

        def alg = new GcmAesAeadAlgorithm(256)

        def iv = new byte[12]
        Randoms.secureRandom().nextBytes(iv)

        def kek = alg.key().build()
        def cek = alg.key().build()

        final String jcaName = "AES/GCM/NoPadding"

        JcaTemplate template = new JcaTemplate(jcaName)
        byte[] jcaResult = template.withCipher(new CheckedFunction<Cipher, byte[]>() {
            @Override
            byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, iv))
                return cipher.wrap(cek)
            }
        })

        //separate tag from jca ciphertext:
        int ciphertextLength = jcaResult.length - 16 //AES block size in bytes (128 bits)
        byte[] ciphertext = new byte[ciphertextLength]
        System.arraycopy(jcaResult, 0, ciphertext, 0, ciphertextLength)

        byte[] tag = new byte[16]
        System.arraycopy(jcaResult, ciphertextLength, tag, 0, 16)
        def resultA = new DefaultAeadResult(null, null, ciphertext, kek, null, tag, iv)

        def encRequest = new DefaultAeadRequest(cek.getEncoded(), null, null, kek, null, iv)
        def encResult = Jwts.ENC.A256GCM.encrypt(encRequest)

        assertArrayEquals resultA.digest, encResult.digest
        assertArrayEquals resultA.initializationVector, encResult.initializationVector
        assertArrayEquals resultA.getPayload(), encResult.getPayload()
    }

    static void assertAlgorithm(int keyLength) {

        def alg = new AesGcmKeyAlgorithm(keyLength)
        assertEquals 'A' + keyLength + 'GCMKW', alg.getId()

        def template = new JcaTemplate('AES')

        def header = Jwts.header()
        def kek = template.generateSecretKey(keyLength)
        def cek = template.generateSecretKey(keyLength)
        def enc = new GcmAesAeadAlgorithm(keyLength) {
            @Override
            SecretKeyBuilder key() {
                return Keys.builder(cek)
            }
        }

        def delegate = new DefaultMutableJweHeader(header)
        def ereq = new DefaultKeyRequest(kek, null, null, delegate, enc)

        def result = alg.getEncryptionKey(ereq)

        byte[] encryptedKeyBytes = result.getPayload()
        assertFalse "encryptedKey must be populated", Arrays.length(encryptedKeyBytes) == 0

        def jweHeader = header.build() as JweHeader

        def dcek = alg.getDecryptionKey(new DefaultDecryptionKeyRequest(encryptedKeyBytes, null, null, jweHeader, enc, kek))

        //Assert the decrypted key matches the original cek
        assertEquals cek.algorithm, dcek.algorithm
        assertArrayEquals cek.encoded, dcek.encoded
    }

    @Test
    void testResultSymmetry() {
        assertAlgorithm(128)
        assertAlgorithm(192)
        assertAlgorithm(256)
    }

    static void testDecryptionHeader(String headerName, Object value, String exmsg) {
        int keyLength = 128
        def alg = new AesGcmKeyAlgorithm(keyLength)
        def template = new JcaTemplate('AES')
        def headerBuilder = Jwts.header()
        def kek = template.generateSecretKey(keyLength)
        def cek = template.generateSecretKey(keyLength)
        def enc = new GcmAesAeadAlgorithm(keyLength) {
            @Override
            SecretKeyBuilder key() {
                return Keys.builder(cek)
            }
        }
        def delegate = new DefaultMutableJweHeader(headerBuilder)
        def ereq = new DefaultKeyRequest(kek, null, null, delegate, enc)
        def result = alg.getEncryptionKey(ereq)

        headerBuilder.remove(headerName)

        headerBuilder.put(headerName, value)

        byte[] encryptedKeyBytes = result.getPayload()

        def header = headerBuilder.build() as JweHeader

        try {
            alg.getDecryptionKey(new DefaultDecryptionKeyRequest(encryptedKeyBytes, null, null, header, enc, kek))
            fail()
        } catch (MalformedJwtException iae) {
            assertEquals exmsg, iae.getMessage()
        }
    }

    static String missing(String id, String name) {
        return "JWE header is missing required '$id' ($name) value." as String
    }

    static String type(String name) {
        return "JWE header '${name}' value must be a String. Actual type: java.lang.Integer" as String
    }

    static String length(String name, int requiredBitLength) {
        return "JWE header '${name}' decoded byte array must be ${Bytes.bitsMsg(requiredBitLength)} long. Actual length: ${Bytes.bitsMsg(16)}."
    }

    @Test
    void testMissingHeaders() {
        testDecryptionHeader('iv', null, missing('iv', 'Initialization Vector'))
        testDecryptionHeader('tag', null, missing('tag', 'Authentication Tag'))
    }
}
