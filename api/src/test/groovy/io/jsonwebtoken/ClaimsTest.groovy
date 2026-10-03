/*
 * Copyright (C) 2026 jsonwebtoken.io
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

import java.time.Instant

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNull

class ClaimsTest {

    private static final Date DATE = new Date(1700000000123L)

    private static Claims legacyClaims(Date exp, Date nbf, Date iat) {
        return [
                getExpiration: { -> exp },
                getNotBefore : { -> nbf },
                getIssuedAt  : { -> iat }
        ] as Claims
    }

    @Test
    void testDefaultExpiration() {
        assertEquals DATE.toInstant(), legacyClaims(DATE, null, null).expiration()
    }

    @Test
    void testDefaultExpirationNull() {
        assertNull legacyClaims(null, DATE, DATE).expiration()
    }

    @Test
    void testDefaultNotBefore() {
        assertEquals DATE.toInstant(), legacyClaims(null, DATE, null).notBefore()
    }

    @Test
    void testDefaultNotBeforeNull() {
        assertNull legacyClaims(DATE, null, DATE).notBefore()
    }

    @Test
    void testDefaultIssuedAt() {
        assertEquals DATE.toInstant(), legacyClaims(null, null, DATE).issuedAt()
    }

    @Test
    void testDefaultIssuedAtNull() {
        assertNull legacyClaims(DATE, DATE, null).issuedAt()
    }

    @Test
    void testDefaultInstantAccessorsPreserveMillis() {
        def claims = legacyClaims(new Date(1L), new Date(2L), new Date(3L))
        assertEquals Instant.ofEpochMilli(1L), claims.expiration()
        assertEquals Instant.ofEpochMilli(2L), claims.notBefore()
        assertEquals Instant.ofEpochMilli(3L), claims.issuedAt()
    }
}
