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

class JwtBuilderTest {

    private static final Instant INSTANT = Instant.ofEpochMilli(1700000000123L)

    @Test
    void testDefaultExpirationDelegatesToDate() {
        def builder = legacyBuilder()
        assertSame builder, builder.expiration(INSTANT)
        assertEquals Date.from(INSTANT), builder.values.exp
    }

    @Test
    void testDefaultExpirationNull() {
        def builder = legacyBuilder()
        assertSame builder, builder.expiration((Instant) null)
        assertTrue builder.values.containsKey('exp')
        assertNull builder.values.exp
    }

    @Test
    void testDefaultNotBeforeDelegatesToDate() {
        def builder = legacyBuilder()
        assertSame builder, builder.notBefore(INSTANT)
        assertEquals Date.from(INSTANT), builder.values.nbf
    }

    @Test
    void testDefaultNotBeforeNull() {
        def builder = legacyBuilder()
        assertSame builder, builder.notBefore((Instant) null)
        assertTrue builder.values.containsKey('nbf')
        assertNull builder.values.nbf
    }

    @Test
    void testDefaultIssuedAtDelegatesToDate() {
        def builder = legacyBuilder()
        assertSame builder, builder.issuedAt(INSTANT)
        assertEquals Date.from(INSTANT), builder.values.iat
    }

    @Test
    void testDefaultIssuedAtNull() {
        def builder = legacyBuilder()
        assertSame builder, builder.issuedAt((Instant) null)
        assertTrue builder.values.containsKey('iat')
        assertNull builder.values.iat
    }

    /**
     * Creates a {@code JwtBuilder} written before the {@code Instant} variants existed: only the {@code Date}
     * methods are implemented (by {@link LegacyJwtBuilder}); Groovy generates the remaining abstract methods, so the
     * {@code Instant} methods run their interface default implementations.
     */
    private static LegacyJwtBuilder legacyBuilder() {
        return [:] as LegacyJwtBuilder
    }

    static abstract class LegacyJwtBuilder implements JwtBuilder {

        Map<String, Date> values = [:]

        @Override
        JwtBuilder expiration(Date exp) {
            values.exp = exp
            return this
        }

        @Override
        JwtBuilder notBefore(Date nbf) {
            values.nbf = nbf
            return this
        }

        @Override
        JwtBuilder issuedAt(Date iat) {
            values.iat = iat
            return this
        }
    }
}
