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
package io.jsonwebtoken.impl

import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.Jwts
import org.junit.Test

import static org.junit.Assert.*

class DefaultJwsTest {

    @Test
    void testConstructor() {
        JwsHeader header = new DefaultJwsHeader([:])
        def jws = new DefaultJws<String>(header, 'foo', 'sig')
        assertSame jws.getHeader(), header
        assertEquals jws.getPayload(), 'foo'
        assertEquals jws.getSignature(), 'sig'
    }

    @Test
    void testToString() {
        //create random signing key for testing:
        def alg = Jwts.SIG.HS256
        def key = alg.key().build()
        String compact = Jwts.builder().claim('foo', 'bar').signWith(key, alg).compact()
        int i = compact.lastIndexOf('.')
        String signature = compact.substring(i + 1)
        def jws = Jwts.parser().verifyWith(key).build().parseClaimsJws(compact)
        assertEquals 'header={alg=HS256},payload={foo=bar},signature=' + signature, jws.toString()
    }

    @Test
    void testEqualsAndHashCode() {
        def alg = Jwts.SIG.HS256
        def key = alg.key().build()
        String compact = Jwts.builder().claim('foo', 'bar').signWith(key, alg).compact()
        def parser = Jwts.parser().verifyWith(key).build()
        def jws1 = parser.parseClaimsJws(compact)
        def jws2 = parser.parseClaimsJws(compact)
        assertNotEquals jws1, 'hello' as String
        assertEquals jws1, jws1
        assertEquals jws2, jws2
        assertEquals jws1, jws2
        assertEquals jws1.hashCode(), jws2.hashCode()
    }
}
