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

import static org.junit.Assert.*

class ClaimsMutatorTest {

    private static final Instant INSTANT = Instant.ofEpochMilli(1700000000123L)

    @Test
    void testDefaultExpirationDelegatesToDate() {
        def m = new LegacyMutator()
        assertSame m, m.expiration(INSTANT)
        assertEquals Date.from(INSTANT), m.values.exp
    }

    @Test
    void testDefaultExpirationNull() {
        def m = new LegacyMutator()
        assertSame m, m.expiration((Instant) null)
        assertTrue m.values.containsKey('exp')
        assertNull m.values.exp
    }

    @Test
    void testDefaultNotBeforeDelegatesToDate() {
        def m = new LegacyMutator()
        assertSame m, m.notBefore(INSTANT)
        assertEquals Date.from(INSTANT), m.values.nbf
    }

    @Test
    void testDefaultNotBeforeNull() {
        def m = new LegacyMutator()
        assertSame m, m.notBefore((Instant) null)
        assertTrue m.values.containsKey('nbf')
        assertNull m.values.nbf
    }

    @Test
    void testDefaultIssuedAtDelegatesToDate() {
        def m = new LegacyMutator()
        assertSame m, m.issuedAt(INSTANT)
        assertEquals Date.from(INSTANT), m.values.iat
    }

    @Test
    void testDefaultIssuedAtNull() {
        def m = new LegacyMutator()
        assertSame m, m.issuedAt((Instant) null)
        assertTrue m.values.containsKey('iat')
        assertNull m.values.iat
    }

    /**
     * A {@code ClaimsMutator} implementation written before the {@code Instant} variants existed: it only
     * implements the {@code Date} methods, so the {@code Instant} ones fall back to the interface defaults.
     */
    static class LegacyMutator implements ClaimsMutator<LegacyMutator> {

        Map<String, Date> values = [:]

        @Override
        LegacyMutator expiration(Date exp) {
            values.exp = exp
            return this
        }

        @Override
        LegacyMutator notBefore(Date nbf) {
            values.nbf = nbf
            return this
        }

        @Override
        LegacyMutator issuedAt(Date iat) {
            values.iat = iat
            return this
        }

        @Override
        LegacyMutator setExpiration(Date exp) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator setNotBefore(Date nbf) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator setIssuedAt(Date iat) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator setIssuer(String iss) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator issuer(String iss) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator setSubject(String sub) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator subject(String sub) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator setAudience(String aud) { throw new UnsupportedOperationException() }

        @Override
        AudienceCollection<LegacyMutator> audience() { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator setId(String jti) { throw new UnsupportedOperationException() }

        @Override
        LegacyMutator id(String jti) { throw new UnsupportedOperationException() }
    }
}
