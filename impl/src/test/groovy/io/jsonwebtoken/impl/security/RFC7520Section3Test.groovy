/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.SecretKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

/**
 * Tests successful parsing/creation of RFC 7520, Section 3
 * <a href="https://www.rfc-editor.org/rfc/rfc7520.html#section-3">JSON Web Key Examples</a>.
 *
 * @since JJWT_RELEASE_VERSION
 */
class RFC7520Section3Test {

    static final String FIGURE_2 = Strings.trimAllWhitespace('''
    {
      "kty": "EC",
      "kid": "bilbo.baggins@hobbiton.example",
      "use": "sig",
      "crv": "P-521",
      "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9
            A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
      "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy
            SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
      "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb
            KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"
    }''')

    static final String FIGURE_4 = Strings.trimAllWhitespace('''
    {
      "kty": "RSA",
      "kid": "bilbo.baggins@hobbiton.example",
      "use": "sig",
      "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
          -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
          wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
          oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
          3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
          LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
          HdrNP5zw",
      "e": "AQAB",
      "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e
          iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld
          Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b
          MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU
          6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj
          d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc
          OpBrQzwQ",
      "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR
          aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG
          peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8
          bUq0k",
      "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT
          8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an
          V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0
          s7pFc",
      "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q
          1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn
          -RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX
          59ehik",
      "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr
          AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK
          bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK
          T1cYF8",
      "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N
          ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh
          jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP
          z8aaI4"
    }''')

    static final String FIGURE_5 = Strings.trimAllWhitespace('''
    {
      "kty": "oct",
      "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
      "use": "sig",
      "alg": "HS256",
      "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
    }
    ''')

    static final String FIGURE_6 = Strings.trimAllWhitespace('''
    {
      "kty": "oct",
      "kid": "1e571774-2e08-40da-8308-e8d68773842d",
      "use": "enc",
      "alg": "A256GCM",
      "k": "AAPapAv4LbFbiVawEjagUBluYqN5rhna-8nuldDvOx8"
    }
    ''')

    @Test
    void testSection3_1() { // EC Public Key
        String jwkString = Strings.trimAllWhitespace('''
        {
          "kty": "EC",
          "kid": "bilbo.baggins@hobbiton.example",
          "use": "sig",
          "crv": "P-521",
          "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9
                A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
          "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy
                SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
        }''')

        EcPublicJwk jwk = Jwks.parser().build().parse(jwkString) as EcPublicJwk
        assertEquals 'EC', jwk.getType()
        assertEquals 'sig', jwk.getPublicKeyUse()
        assertEquals 'bilbo.baggins@hobbiton.example', jwk.getId()
        assertEquals 'P-521', jwk.get('crv')
        assertTrue jwk.toKey() instanceof ECPublicKey
    }

    @Test
    void testSection3_2() { // EC Private Key
        EcPrivateJwk jwk = Jwks.parser().build().parse(FIGURE_2) as EcPrivateJwk
        assertEquals 'EC', jwk.getType()
        assertEquals 'sig', jwk.getPublicKeyUse()
        assertEquals 'bilbo.baggins@hobbiton.example', jwk.getId()
        assertEquals 'P-521', jwk.get('crv')
        assertTrue jwk.toKey() instanceof ECPrivateKey
    }

    @Test
    void testSection3_3() { // RSA Public Key
        String s = Strings.trimAllWhitespace('''
        {
          "kty": "RSA",
          "kid": "bilbo.baggins@hobbiton.example",
          "use": "sig",
          "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
                -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
                wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
                oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
                3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
                LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
                HdrNP5zw",
          "e": "AQAB"
        }''')

        RsaPublicJwk jwk = Jwks.parser().build().parse(s) as RsaPublicJwk
        assertEquals 'RSA', jwk.getType()
        assertEquals 'sig', jwk.getPublicKeyUse()
        assertEquals 'bilbo.baggins@hobbiton.example', jwk.getId()
        assertEquals 256, Bytes.length(Decoders.BASE64URL.decode(jwk.get('n') as String))
        assertTrue jwk.toKey() instanceof RSAPublicKey
    }

    @Test
    void testSection3_4() { // RSA Private Key
        RsaPrivateJwk jwk = Jwks.parser().build().parse(FIGURE_4) as RsaPrivateJwk
        assertEquals 'RSA', jwk.getType()
        assertEquals 'sig', jwk.getPublicKeyUse()
        assertEquals 'bilbo.baggins@hobbiton.example', jwk.getId()
        assertEquals 256, Bytes.length(Decoders.BASE64URL.decode(jwk.get('n') as String))
        assertTrue Bytes.length(Decoders.BASE64URL.decode(jwk.get('d') as String)) <= 256
        assertTrue jwk.toKey() instanceof RSAPrivateKey
    }

    @Test
    void testSection3_5() { // Symmetric Key (MAC)
        SecretJwk jwk = Jwks.parser().build().parse(FIGURE_5) as SecretJwk
        assertEquals 'oct', jwk.getType()
        assertEquals '018c0ae5-4d9b-471b-bfd6-eef314bc7037', jwk.getId()
        assertEquals 'sig', jwk.get('use')
        assertEquals 'HS256', jwk.getAlgorithm()
        SecretKey key = jwk.toKey()
        assertEquals 256, Bytes.bitLength(key.getEncoded())
    }

    @Test
    void testSection3_6() { // Symmetric Key (Encryption)
        SecretJwk jwk = Jwks.parser().build().parse(FIGURE_6) as SecretJwk
        assertEquals 'oct', jwk.getType()
        assertEquals '1e571774-2e08-40da-8308-e8d68773842d', jwk.getId()
        assertEquals 'enc', jwk.get('use')
        assertEquals 'A256GCM', jwk.getAlgorithm()
        SecretKey key = jwk.toKey()
        assertEquals 256, Bytes.bitLength(key.getEncoded())
    }
}
