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

import io.jsonwebtoken.impl.io.ConvertingParser
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.Provider

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.*

class DefaultJwkParserBuilderTest {

    // This JSON was borrowed from RFC7520Section3Test.FIGURE_2 and modified to
    // replace the 'use' member with 'key_ops` for this test:
    static String UNRELATED_OPS_JSON = Strings.trimAllWhitespace('''
        {
          "kty": "EC",
          "kid": "bilbo.baggins@hobbiton.example",
          "key_ops": ["sign", "encrypt"],
          "crv": "P-521",
          "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9
                A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
          "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy
                SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
          "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb
                KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"
        }''')

    @Test
    void testStaticFactoryMethod() {
        assertTrue Jwks.parser() instanceof DefaultJwkParserBuilder
    }

    @Test
    void testProvider() {
        def provider = createMock(Provider)
        def parser = Jwks.parser().provider(provider).build() as ConvertingParser
        assertSame provider, parser.converter.supplier.provider
    }

    @Test
    void testDeserializer() {
        def deserializer = createMock(Deserializer)
        def parser = Jwks.parser().deserializer(deserializer).build() as ConvertingParser
        assertSame deserializer, parser.deserializer
    }

    @Test
    void testOperationPolicy() {
        def parser = Jwks.parser().build() as ConvertingParser

        try {
            // parse a JWK that has unrelated operations (prevented by default):
            parser.parse(UNRELATED_OPS_JSON)
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Unable to create JWK: Unrelated key operations are not allowed. KeyOperation " +
                    "['encrypt' (Encrypt content)] is unrelated to ['sign' (Compute digital signature or MAC)]."
            assertEquals msg, expected.message
        }
    }

    @Test
    void testOperationPolicyOverride() {
        def policy = Jwks.OP.policy().allowUnrelated(true).build()
        def parser = Jwks.parser().operationPolicy(policy).build()
        assertNotNull parser.parse(UNRELATED_OPS_JSON) // no exception because policy allows it
    }

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
        def provider = TestKeys.BC //always used

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
        def deserializer = new Deserializer() {
            @Override
            Object deserialize(byte[] bytes) throws DeserializationException {
                throw new DeserializationException("test")
            }
        }
        def parser = new DefaultJwkParserBuilder().deserializer(deserializer).build()
        try {
            parser.parse('foo')
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Unable to deserialize JWK: test"
            assertEquals msg, expected.getMessage()
        }
    }
}
