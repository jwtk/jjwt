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
package io.jsonwebtoken.all

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import org.junit.Test

import static org.hamcrest.CoreMatchers.equalTo
import static org.hamcrest.CoreMatchers.notNullValue
import static org.hamcrest.MatcherAssert.assertThat

/**
 * This test ensures that the included dependency are all that is needed to use JJWT.
 */
class BasicTest {

    @Test
    void basicUsageTest() {
        def key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

        String token = Jwts.builder()
            .setSubject("test-user")
            .claim("test", "basicUsageTest")
            .signWith(key, SignatureAlgorithm.HS256)
            .compact()

        JwtParser parser = Jwts.parser()
            .setSigningKey(key)
            .build()

        Jwt<Header, Claims> result = parser.parseClaimsJws(token)
        assertThat result, notNullValue()
        assertThat result.getBody().getSubject(), equalTo("test-user")
        assertThat result.getBody().get("test", String), equalTo("basicUsageTest")
    }
}
