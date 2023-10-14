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

import io.jsonwebtoken.Jwts
import org.junit.Test

import static org.junit.Assert.assertEquals

class Issue858Test {

    @Test
    void testEmptyAndNullEntries() {
        def jwt = Jwts.builder()
                .subject('Joe')
                .claim('foo', '')       // empty allowed
                .claim('list', [])            // empty allowed
                .claim('map', [:])            // empty map allowed
                .claim('another', null) // null not allowed (same behavior since <= 0.11.5), won't be added
                .compact()

        def claims = Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).getPayload()
        assertEquals 4, claims.size()
        assertEquals 'Joe', claims.getSubject()
        assertEquals '', claims.get('foo')
        assertEquals([], claims.get('list'))
        assertEquals([:], claims.get('map'))
    }
}
