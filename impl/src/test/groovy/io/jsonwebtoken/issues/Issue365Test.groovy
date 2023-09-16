/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.issues

import io.jsonwebtoken.Header
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Locator
import io.jsonwebtoken.impl.DefaultJwtBuilder
import io.jsonwebtoken.impl.DefaultJwtParser
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.impl.security.TestPrivateKey
import io.jsonwebtoken.impl.security.TestPublicKey
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.KeyAlgorithm
import io.jsonwebtoken.security.SignatureAlgorithm
import org.junit.Test

import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class Issue365Test {


    private static final Collection<SignatureAlgorithm> sigalgs() {
        def algs = Jwts.SIG.get().values()
                .findAll({ it -> it instanceof SignatureAlgorithm })
        return algs as Collection<SignatureAlgorithm>
    }

    private static final Collection<KeyAlgorithm<PublicKey, PrivateKey>> asymKeyAlgs() {
        def algs = Jwts.KEY.get().values()
                .findAll({ it -> it.id.startsWith('R') || it.id.startsWith('E') })
        return algs as Collection<KeyAlgorithm<PublicKey, PrivateKey>>
    }

    private static final Collection<SignatureAlgorithm> sigalgs = sigalgs()

    private static final Collection<KeyAlgorithm<PublicKey, PrivateKey>> asymKeyAlgs = asymKeyAlgs()

    @Test
    void testSignWithPublicKey() {


        for (def alg : sigalgs) {
            def pair = TestKeys.forAlgorithm(alg).pair
            try {
                Jwts.builder().issuer('me').signWith(pair.public, alg).compact()
                fail()
            } catch (IllegalArgumentException expected) {
                assertEquals DefaultJwtBuilder.PUB_KEY_SIGN_MSG, expected.getMessage()
            }
        }
    }

    @Test
    void testVerifyWithPrivateKey() {
        for (def alg : sigalgs) {
            def pair = TestKeys.forAlgorithm(alg).pair
            String jws = Jwts.builder().issuer('me').signWith(pair.private).compact()
            try {
                Jwts.parser().verifyWith(pair.private).build().parseClaimsJws(jws)
                fail()
            } catch (IllegalArgumentException expected) {
                assertEquals DefaultJwtParser.PRIV_KEY_VERIFY_MSG, expected.getMessage()
            }
        }
    }

    @Test
    void testVerifyWithKeyLocatorPrivateKey() {
        for (def alg : sigalgs) {
            def pair = TestKeys.forAlgorithm(alg).pair
            String jws = Jwts.builder().issuer('me').signWith(pair.private).compact()
            try {
                Jwts.parser().keyLocator(new Locator<Key>() {
                    @Override
                    Key locate(Header header) {
                        return pair.private
                    }
                })
                        .build().parseClaimsJws(jws)
                fail()
            } catch (InvalidKeyException expected) {
                assertEquals DefaultJwtParser.PRIV_KEY_VERIFY_MSG, expected.getMessage()
            }
        }
    }

    @Test
    void testEncryptWithPrivateKey() {
        for (def alg : asymKeyAlgs) {
            try {
                Jwts.builder().issuer('me').encryptWith(new TestPrivateKey(), alg, Jwts.ENC.A256GCM).compact()
                fail()
            } catch (IllegalArgumentException expected) {
                assertEquals DefaultJwtBuilder.PRIV_KEY_ENC_MSG, expected.getMessage()
            }
        }
    }

    @Test
    void testDecryptWithPublicKey() {
        def pub = TestKeys.RS256.pair.public
        String jwe = Jwts.builder().issuer('me').encryptWith(pub, Jwts.KEY.RSA1_5, Jwts.ENC.A256GCM).compact()
        try {
            Jwts.parser().decryptWith(new TestPublicKey()).build().parseClaimsJwe(jwe)
            fail()
        } catch (IllegalArgumentException expected) {
            assertEquals DefaultJwtParser.PUB_KEY_DECRYPT_MSG, expected.getMessage()
        }
    }

    @Test
    void testDecryptWithKeyLocatorPublicKey() {
        def pub = TestKeys.RS256.pair.public
        String jwe = Jwts.builder().issuer('me').encryptWith(pub, Jwts.KEY.RSA1_5, Jwts.ENC.A256GCM).compact()
        try {
            Jwts.parser().keyLocator(new Locator<Key>() {
                @Override
                Key locate(Header header) {
                    return pub
                }
            })
                    .build().parseClaimsJwe(jwe)
            fail()
        } catch (InvalidKeyException expected) {
            assertEquals DefaultJwtParser.PUB_KEY_DECRYPT_MSG, expected.getMessage()
        }
    }
}
