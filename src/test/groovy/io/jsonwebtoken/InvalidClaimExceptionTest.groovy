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

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class InvalidClaimExceptionTest {

    @Test
    void testOverloadedConstructor() {
        def header = Jwts.header()
        def claims = Jwts.claims()
        def msg = 'foo'
        def cause = new NullPointerException()

        def claimName = 'cName'
        def claimValue = 'cValue'

        def ex = new InvalidClaimException(header, claims, msg, cause)
        ex.setClaimName(claimName)
        ex.setClaimValue(claimValue)

        assertSame ex.header, header
        assertSame ex.claims, claims
        assertEquals ex.message, msg
        assertSame ex.cause, cause
        assertEquals ex.claimName, claimName
        assertEquals ex.claimValue, claimValue
    }
}
