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

import io.jsonwebtoken.impl.lang.Conditions
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.Key

import static org.junit.Assert.*

class DefaultJwkParserTest {

    @Test
    void testKeys() {

        Set<Key> keys = new LinkedHashSet<>()
        TestKeys.SECRET.each { keys.add(it) }
        TestKeys.ASYM.each {
            keys.add(it.pair.public)
            keys.add(it.pair.private)
        }

        def serializer = Services.loadFirst(Serializer)
        for (Key key : keys) {
            //noinspection GroovyAssignabilityCheck
            def jwk = Jwks.builder().key(key).build()
            def data = serializer.serialize(jwk)
            String json = new String(data, StandardCharsets.UTF_8)
            def parsed = Jwks.parser().build().parse(json)
            assertEquals jwk, parsed
        }
    }

    @Test
    void testKeysWithProvider() {

        Set<Key> keys = new LinkedHashSet<>()
        TestKeys.HS.each { keys.add(it) }
        TestKeys.ASYM.each {
            keys.add(it.pair.public)
            keys.add(it.pair.private)
        }

        def serializer = Services.loadFirst(Serializer)
        def provider = Providers.findBouncyCastle(Conditions.TRUE) //always used

        for (Key key : keys) {
            //noinspection GroovyAssignabilityCheck
            def jwk = Jwks.builder().provider(provider).key(key).build()
            def data = serializer.serialize(jwk)
            String json = new String(data, StandardCharsets.UTF_8)
            def parsed = Jwks.parser().provider(provider).build().parse(json)
            assertEquals jwk, parsed
            assertSame provider, parsed.@context.@provider
        }
    }

    @Test
    void testDeserializationFailure() {
        def parser = new DefaultJwkParser(null, Services.loadFirst(Deserializer)) {
            @Override
            protected Map<String, ?> deserialize(String json) {
                throw new DeserializationException("test")
            }
        }
        try {
            parser.parse('foo')
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Unable to deserialize JSON string argument: test"
            assertEquals msg, expected.getMessage()
        }
    }
}
