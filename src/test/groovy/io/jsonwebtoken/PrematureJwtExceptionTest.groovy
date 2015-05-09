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

import org.junit.Test
import static org.junit.Assert.*

class PrematureJwtExceptionTest {

    @Test
    void testOverloadedConstructor() {
        def header = Jwts.header()
        def claims = Jwts.claims()
        def msg = 'foo'
        def cause = new NullPointerException()

        def ex = new PrematureJwtException(header, claims, msg, cause)

        assertSame ex.header, header
        assertSame ex.claims, claims
        assertEquals ex.message, msg
        assertSame ex.cause, cause
    }
}
