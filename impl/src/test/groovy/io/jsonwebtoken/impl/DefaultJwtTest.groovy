/*
 * Copyright (C) 2014 jsonwebtoken.io
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

import io.jsonwebtoken.Jwt
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Encoders
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotEquals

class DefaultJwtTest {

    @Test
    void testToString() {
        String compact = Jwts.builder().header().add('foo', 'bar').and().audience('jsmith').compact()
        Jwt jwt = Jwts.parser().enableUnsecured().build().parseClaimsJwt(compact)
        assertEquals 'header={foo=bar, alg=none},payload={aud=[jsmith]}', jwt.toString()
    }

    @Test
    void testByteArrayPayloadToString() {
        byte[] bytes = 'hello JJWT'.getBytes(StandardCharsets.UTF_8)
        String encoded = Encoders.BASE64URL.encode(bytes)
        String compact = Jwts.builder().header().add('foo', 'bar').and().content(bytes).compact()
        Jwt jwt = Jwts.parser().enableUnsecured().build().parseContentJwt(compact)
        assertEquals "header={foo=bar, alg=none},payload=$encoded" as String, jwt.toString()
    }

    @Test
    void testEqualsAndHashCode() {
        String compact = Jwts.builder().claim('foo', 'bar').compact()
        def parser = Jwts.parser().enableUnsecured().build()
        def jwt1 = parser.parseClaimsJwt(compact)
        def jwt2 = parser.parseClaimsJwt(compact)
        assertNotEquals jwt1, 'hello' as String
        assertEquals jwt1, jwt1
        assertEquals jwt2, jwt2
        assertEquals jwt1, jwt2
        assertEquals jwt1.hashCode(), jwt2.hashCode()
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testBodyAndPayloadSame() {
        String compact = Jwts.builder().claim('foo', 'bar').compact()
        def parser = Jwts.parser().enableUnsecured().build()
        def jwt1 = parser.parseClaimsJwt(compact)
        def jwt2 = parser.parseClaimsJwt(compact)
        assertEquals jwt1.getBody(), jwt1.getPayload()
        assertEquals jwt2.getBody(), jwt2.getPayload()
        assertEquals jwt1.getBody(), jwt2.getBody()
        assertEquals jwt1.getPayload(), jwt2.getPayload()
    }
}
