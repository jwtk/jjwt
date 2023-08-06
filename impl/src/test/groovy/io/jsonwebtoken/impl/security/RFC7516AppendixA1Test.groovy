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
 * Tests successful parsing/decryption of a 'JWE using RSAES-OAEP and AES GCM' as defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1">RFC 7516, Appendix A.1</a>
 *
 * @since JJWT_RELEASE_VERSION
 */
class RFC7516AppendixA1Test {

    static String encode(byte[] b) {
        return Encoders.BASE64URL.encode(b)
    }

    static byte[] decode(String val) {
        return Decoders.BASE64URL.decode(val)
    }

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1 :
    final static String PLAINTEXT = 'The true sign of intelligence is not knowledge but imagination.' as String
    final static byte[] PLAINTEXT_BYTES = [84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
                                           111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
                                           101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
                                           101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
                                           110, 97, 116, 105, 111, 110, 46] as byte[]

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1.1 :
    final static String PROT_HEADER_STRING = '{"alg":"RSA-OAEP","enc":"A256GCM"}' as String
    final static String encodedHeader = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ' as String

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1.2
    final static byte[] CEK_BYTES = [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
                                     212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
                                     234, 64, 252] as byte[]
    final static SecretKey CEK = new SecretKeySpec(CEK_BYTES, "AES")

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1.3
    final static Map<String, String> KEK_VALUES = [
            "kty": "RSA",
            "n"  : "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW" +
                    "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S" +
                    "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a" +
                    "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS" +
                    "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj" +
                    "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
            "e"  : "AQAB",
            "d"  : "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N" +
                    "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9" +
                    "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk" +
                    "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl" +
                    "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd" +
                    "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
            "p"  : "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-" +
                    "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf" +
                    "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
            "q"  : "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm" +
                    "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX" +
                    "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
            "dp" : "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL" +
                    "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827" +
                    "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
            "dq" : "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj" +
                    "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB" +
                    "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
            "qi" : "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7" +
                    "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3" +
                    "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
    ]

    final static byte[] ENCRYPTED_CEK_BYTES = [56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
                                               22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
                                               82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
                                               145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
                                               74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
                                               13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
                                               173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
                                               89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
                                               243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
                                               41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
                                               215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
                                               63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
                                               193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
                                               206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
                                               104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
                                               89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
                                               172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
                                               117, 114, 135, 206] as byte[]

    final static String encodedEncryptedCek = 'OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe' +
            'ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb' +
            'Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV' +
            'mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8' +
            '1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi' +
            '6UklfCpIMfIjf7iGdXKHzg' as String

    // https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1.4
    final static byte[] IV = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219] as byte[]
    final static String encodedIv = '48V1_ALb6US04U3b' as String

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1.5
    final static byte[] AAD_BYTES = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
                                     116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
                                     54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81] as byte[]

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1.6
    final static byte[] CIPHERTEXT = [229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
                                      233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
                                      104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
                                      123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
                                      160, 109, 64, 63, 192] as byte[]
    final static String encodedCiphertext =
            '5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A' as String

    final static byte[] TAG = [92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145] as byte[]
    final static String encodedTag = 'XFBoMYUZodetZdvTiFvSkQ'

    // defined in https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.1.7
    final static String COMPLETE_JWE = '' +
            'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.' +
            'OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe' +
            'ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb' +
            'Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV' +
            'mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8' +
            '1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi' +
            '6UklfCpIMfIjf7iGdXKHzg.' +
            '48V1_ALb6US04U3b.' +
            '5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji' +
            'SdiwkIr3ajwQzaBtQD_A.' +
            'XFBoMYUZodetZdvTiFvSkQ' as String

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
