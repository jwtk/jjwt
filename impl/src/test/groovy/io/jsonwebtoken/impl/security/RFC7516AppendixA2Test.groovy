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
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.RsaPrivateJwk
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.interfaces.RSAPrivateKey

import static org.junit.Assert.assertArrayEquals
import static org.junit.Assert.assertEquals

/**
 * Tests successful parsing/decryption of a 'JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256' as defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2">RFC 7516, Appendix A.2</a>
 *
 * @since JJWT_RELEASE_VERSION
 */
class RFC7516AppendixA2Test {

    static String encode(byte[] b) {
        return Encoders.BASE64URL.encode(b)
    }

    static byte[] decode(String val) {
        return Decoders.BASE64URL.decode(val)
    }

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2 :
    final static String PLAINTEXT = 'Live long and prosper.' as String
    final static byte[] PLAINTEXT_BYTES = [76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
                                           112, 114, 111, 115, 112, 101, 114, 46] as byte[]

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.1 :
    final static String PROT_HEADER_STRING = '{"alg":"RSA1_5","enc":"A128CBC-HS256"}' as String
    final static String encodedHeader = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0' as String

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.2
    final static byte[] CEK_BYTES = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
                                     206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
                                     44, 207] as byte[]
    final static SecretKey CEK = new SecretKeySpec(CEK_BYTES, "AES")

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.3
    final static Map<String, String> KEK_VALUES = [
            "kty": "RSA",
            "n"  : "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
                    "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
                    "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
                    "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
                    "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
                    "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e"  : "AQAB",
            "d"  : "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq" +
                    "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry" +
                    "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_" +
                    "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj" +
                    "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj" +
                    "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
            "p"  : "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68" +
                    "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP" +
                    "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
            "q"  : "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y" +
                    "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN" +
                    "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
            "dp" : "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv" +
                    "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra" +
                    "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
            "dq" : "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff" +
                    "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_" +
                    "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
            "qi" : "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC" +
                    "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ" +
                    "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
    ]

    final static byte[] ENCRYPTED_CEK_BYTES = [80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151,
                                               176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181,
                                               156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156,
                                               116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223,
                                               226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66,
                                               212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253,
                                               215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128,
                                               66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199,
                                               54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151,
                                               250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197,
                                               21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102,
                                               166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222,
                                               150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241,
                                               124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242,
                                               16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244,
                                               248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167,
                                               101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169,
                                               146, 114, 165, 204, 71, 136, 41, 252] as byte[]

    final static String encodedEncryptedCek = 'UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm' +
            '1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc' +
            'HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF' +
            'NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8' +
            'rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv' +
            '-B3oWh2TbqmScqXMR4gp_A' as String

    // https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.4
    final static byte[] IV = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101] as byte[]
    final static String encodedIv = 'AxY8DCtDaGlsbGljb3RoZQ' as String

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.5
    final static byte[] AAD_BYTES = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
                                     120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
                                     74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
                                     50, 73, 110, 48] as byte[]

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.6
    final static byte[] CIPHERTEXT = [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
                                      75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
                                      112, 56, 102] as byte[]
    final static String encodedCiphertext = 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY' as String

    final static byte[] TAG = [246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100, 191] as byte[]
    final static String encodedTag = '9hH0vgRfYgPnAHOd8stkvw'

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.2.7
    final static String COMPLETE_JWE =
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                    "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm" +
                    "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc" +
                    "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF" +
                    "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8" +
                    "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv" +
                    "-B3oWh2TbqmScqXMR4gp_A." +
                    "AxY8DCtDaGlsbGljb3RoZQ." +
                    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
                    "9hH0vgRfYgPnAHOd8stkvw" as String

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
        RsaPrivateJwk jwk = Jwks.builder().add(KEK_VALUES).build() as RsaPrivateJwk
        RSAPrivateKey privKey = jwk.toKey()

        Jwe<byte[]> jwe = Jwts.parser().decryptWith(privKey).build().parseContentJwe(COMPLETE_JWE)
        assertEquals PLAINTEXT, new String(jwe.getPayload(), StandardCharsets.UTF_8)
    }
}
