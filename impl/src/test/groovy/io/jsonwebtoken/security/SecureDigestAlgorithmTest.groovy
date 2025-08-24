/*
 * Copyright © 2025 jsonwebtoken.io
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
package io.jsonwebtoken.security

import io.jsonwebtoken.Jwts
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertTrue

class SecureDigestAlgorithmTest {

    // only need one each of mac algorithm and signature algorithm - no need to take time for key generation
    static final def algs = [Jwts.SIG.HS256, Jwts.SIG.ES256]

    @Test
    void testRoundtrip() {

        final msg = 'hello world'
        final is = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8))

        algs.each { alg ->
            def skey
            def vkey

            if (alg instanceof KeyPairBuilderSupplier) {
                def pair = alg.keyPair().build()
                skey = pair.getPrivate()
                vkey = pair.getPublic()
            } else {
                skey = vkey = alg.key().build()
            }

            byte[] digest = alg.digest(skey, is)
            is.reset()
            assertTrue alg.verify(vkey, is, digest)
            is.reset()
        }
    }
}
