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
package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.AeadAlgorithm
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotEquals

class DefaultJweTest {

    @Test
    void testToString() {
        def alg = Jwts.ENC.A128CBC_HS256 as AeadAlgorithm
        def key = alg.key().build()
        String compact = Jwts.builder().claim('foo', 'bar').encryptWith(key, alg).compact()
        def jwe = Jwts.parser().decryptWith(key).build().parseClaimsJwe(compact)
        String encodedIv = Encoders.BASE64URL.encode(jwe.initializationVector)
        String encodedTag = Encoders.BASE64URL.encode(jwe.digest)
        String expected = "header={alg=dir, enc=A128CBC-HS256},payload={foo=bar},tag=$encodedTag,iv=$encodedIv"
        assertEquals expected, jwe.toString()
    }

    @Test
    void testEqualsAndHashCode() {
        def alg = Jwts.ENC.A128CBC_HS256 as AeadAlgorithm
        def key = alg.key().build()
        String compact = Jwts.builder().claim('foo', 'bar').encryptWith(key, alg).compact()
        def parser = Jwts.parser().decryptWith(key).build()
        def jwe1 = parser.parseClaimsJwe(compact)
        def jwe2 = parser.parseClaimsJwe(compact)
        assertNotEquals jwe1, 'hello' as String
        assertEquals jwe1, jwe1
        assertEquals jwe2, jwe2
        assertEquals jwe1, jwe2
        assertEquals jwe1.hashCode(), jwe2.hashCode()
    }
}
