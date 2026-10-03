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

class JwtParserBuilderTest {

    private static final Instant INSTANT = Instant.ofEpochMilli(1700000000123L)

    @Test
    void testDefaultRequireIssuedAtDelegatesToDate() {
        def builder = legacyBuilder()
        assertSame builder, builder.requireIssuedAt(INSTANT)
        assertEquals Date.from(INSTANT), builder.values.iat
    }

    @Test
    void testDefaultRequireIssuedAtNull() {
        def builder = legacyBuilder()
        assertSame builder, builder.requireIssuedAt((Instant) null)
        assertTrue builder.values.containsKey('iat')
        assertNull builder.values.iat
    }

    @Test
    void testDefaultRequireExpirationDelegatesToDate() {
        def builder = legacyBuilder()
        assertSame builder, builder.requireExpiration(INSTANT)
        assertEquals Date.from(INSTANT), builder.values.exp
    }

    @Test
    void testDefaultRequireExpirationNull() {
        def builder = legacyBuilder()
        assertSame builder, builder.requireExpiration((Instant) null)
        assertTrue builder.values.containsKey('exp')
        assertNull builder.values.exp
    }

    @Test
    void testDefaultRequireNotBeforeDelegatesToDate() {
        def builder = legacyBuilder()
        assertSame builder, builder.requireNotBefore(INSTANT)
        assertEquals Date.from(INSTANT), builder.values.nbf
    }

    @Test
    void testDefaultRequireNotBeforeNull() {
        def builder = legacyBuilder()
        assertSame builder, builder.requireNotBefore((Instant) null)
        assertTrue builder.values.containsKey('nbf')
        assertNull builder.values.nbf
    }

    /**
     * Creates a {@code JwtParserBuilder} written before the {@code Instant} variants existed: only the
     * {@code Date} methods are implemented (by {@link LegacyJwtParserBuilder}); Groovy generates the remaining
     * abstract methods, so the {@code Instant} methods run their interface default implementations.
     */
    private static LegacyJwtParserBuilder legacyBuilder() {
        return [:] as LegacyJwtParserBuilder
    }

    static abstract class LegacyJwtParserBuilder implements JwtParserBuilder {

        Map<String, Date> values = [:]

        @Override
        JwtParserBuilder requireIssuedAt(Date issuedAt) {
            values.iat = issuedAt
            return this
        }

        @Override
        JwtParserBuilder requireExpiration(Date expiration) {
            values.exp = expiration
            return this
        }

        @Override
        JwtParserBuilder requireNotBefore(Date notBefore) {
            values.nbf = notBefore
            return this
        }
    }
}
