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

import io.jsonwebtoken.Jwe
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.assertEquals

class RFC7516AppendixA3Test {

    static String encode(byte[] b) {
        return Encoders.BASE64URL.encode(b)
    }

    static byte[] decode(String val) {
        return Decoders.BASE64URL.decode(val)
    }

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3 :
    final static String PLAINTEXT = 'Live long and prosper.' as String
    final static byte[] PLAINTEXT_BYTES = [76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
                                           112, 114, 111, 115, 112, 101, 114, 46] as byte[]

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3.1 :
    final static String PROT_HEADER_STRING = '{"alg":"A128KW","enc":"A128CBC-HS256"}' as String
    final static String encodedHeader = 'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0' as String

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.2
    final static byte[] CEK_BYTES = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
                                     206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
                                     44, 207] as byte[]
    final static SecretKey CEK = new SecretKeySpec(CEK_BYTES, "AES")

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3.3
    final static Map<String, String> KEK_VALUES = [
            "kty": "oct",
            "k"  : "GawgguFyGrWKav7AX4VKUg"
    ]

    final static byte[] ENCRYPTED_CEK_BYTES = [232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
                                               22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
                                               76, 124, 193, 11, 98, 37, 173, 61, 104, 57] as byte[]

    final static String encodedEncryptedCek = '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ' as String

    // https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3.4
    final static byte[] IV = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101] as byte[]
    final static String encodedIv = 'AxY8DCtDaGlsbGljb3RoZQ' as String

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3.5
    final static byte[] AAD_BYTES = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
                                     83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
                                     77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
                                     110, 48] as byte[]

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3.6
    final static byte[] CIPHERTEXT = [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
                                      75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
                                      112, 56, 102] as byte[]
    final static String encodedCiphertext = 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY' as String

    final static byte[] TAG = [83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38, 194, 85] as byte[]
    final static String encodedTag = 'U0m_YmjN04DJvceFICbCVQ'

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3.7
    final static String COMPLETE_JWE =
            'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.' +
                    '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.' +
                    'AxY8DCtDaGlsbGljb3RoZQ.' +
                    'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.' +
                    'U0m_YmjN04DJvceFICbCVQ' as String

    @Test
    void test() {
        //ensure our test constants are correctly copied and match the RFC values:
        assertEquals PLAINTEXT, new String(PLAINTEXT_BYTES, StandardCharsets.UTF_8)
        assertEquals PROT_HEADER_STRING, new String(decode(encodedHeader), StandardCharsets.UTF_8)
        assertEquals encodedEncryptedCek, encode(ENCRYPTED_CEK_BYTES)
        assertEquals encodedIv, encode(IV)
        assertArrayEquals AAD_BYTES, encodedHeader.getBytes(StandardCharsets.US_ASCII)
        assertArrayEquals CIPHERTEXT, decode(encodedCiphertext)
        assertArrayEquals TAG, decode(encodedTag)

        //read the RFC Test JWK to get the private key for decrypting
        SecretJwk jwk = Jwks.builder().add(KEK_VALUES).build() as SecretJwk
        SecretKey kek = jwk.toKey()

        // test decryption per the RFC
        Jwe<byte[]> jwe = Jwts.parser().decryptWith(kek).build().parseContentJwe(COMPLETE_JWE)
        assertEquals PLAINTEXT, new String(jwe.getPayload(), StandardCharsets.UTF_8)

        // now ensure that when JJWT does the encryption (i.e. a compact value is produced from JJWT, not from the RFC text),
        // that the resulting compact string is identical to the RFC as described in
        // https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3.8 :

        //ensure that the algorithm reflects the test harness values:
        AeadAlgorithm enc = new HmacAesAeadAlgorithm(128) {
            @Override
            protected byte[] ensureInitializationVector(Request request) {
                return IV
            }

            @Override
            SecretKeyBuilder key() {
                return Keys.builder(CEK)
            }
        }

        String compact = Jwts.builder()
                .setPayload(PLAINTEXT)
                .encryptWith(kek, Jwts.KEY.A128KW, enc)
                .compact()

        assertEquals COMPLETE_JWE, compact
    }
}
