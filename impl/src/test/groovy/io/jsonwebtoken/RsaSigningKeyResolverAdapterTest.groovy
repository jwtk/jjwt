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

import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class RsaSigningKeyResolverAdapterTest {

    @Test
    void testResolveClaimsSigningKeyWithRsaKey() {

        def alg = SignatureAlgorithm.RS256

        def pair = Keys.keyPairFor(alg)

        def compact = Jwts.builder().claim('foo', 'bar').signWith(pair.private, alg).compact()

        Jws<Claims> jws = Jwts.parser().setSigningKey(pair.public).build().parseClaimsJws(compact)

        try {
            new SigningKeyResolverAdapter().resolveSigningKey(jws.header, jws.payload)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "The default resolveSigningKey(JwsHeader, Claims) implementation cannot be used for asymmetric key algorithms (RSA, Elliptic Curve).  Override the resolveSigningKey(JwsHeader, Claims) method instead and return a Key instance appropriate for the RS256 algorithm.", iae.message
        }
    }
}
