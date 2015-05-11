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
package io.jsonwebtoken

import io.jsonwebtoken.impl.crypto.RsaProvider
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class SigningKeyResolverAdapterTest {

    @Test
    void testResolveClaimsSigningKeyWithRsaKey() {

        def pair = RsaProvider.generateKeyPair(1024) //real apps should use 4096 or better.  We're only reducing the size here so the tests are fast

        def compact = Jwts.builder().claim('foo', 'bar').signWith(SignatureAlgorithm.RS256, pair.private).compact()

        Jws<Claims> jws = Jwts.parser().setSigningKey(pair.public).parseClaimsJws(compact)

        try {
            new SigningKeyResolverAdapter().resolveSigningKey(jws.header, jws.body)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "The default resolveSigningKey(JwsHeader, Claims) implementation cannot be used for asymmetric key algorithms (RSA, Elliptic Curve).  Override the resolveSigningKey(JwsHeader, Claims) method instead and return a Key instance appropriate for the RS256 algorithm.", iae.message
        }
    }
}
