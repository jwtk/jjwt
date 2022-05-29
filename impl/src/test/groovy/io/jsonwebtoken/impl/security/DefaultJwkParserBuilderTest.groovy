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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.security.Provider

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class DefaultJwkParserBuilderTest {

    @Test
    void testDefault() {
        def builder = Jwks.parserBuilder() as DefaultJwkParserBuilder
        assertNotNull builder
        assertNull builder.provider
        assertNull builder.deserializer
        def parser = builder.build() as DefaultJwkParser
        assertNull parser.provider
        assertNotNull parser.deserializer // Services.loadFirst should have picked one up
    }

    @Test
    void testProvider() {
        def provider = createMock(Provider)
        def parser = Jwks.parserBuilder().setProvider(provider).build() as DefaultJwkParser
        assertSame provider, parser.provider
    }

    @Test
    void testDeserializer() {
        def deserializer = createMock(Deserializer)
        def parser = Jwks.parserBuilder().deserializeJsonWith(deserializer).build() as DefaultJwkParser
        assertSame deserializer, parser.deserializer
    }
}
