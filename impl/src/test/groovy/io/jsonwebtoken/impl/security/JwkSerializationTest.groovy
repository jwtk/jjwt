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

import io.jsonwebtoken.gson.io.GsonDeserializer
import io.jsonwebtoken.gson.io.GsonSerializer
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.jackson.io.JacksonDeserializer
import io.jsonwebtoken.jackson.io.JacksonSerializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.lang.Supplier
import io.jsonwebtoken.orgjson.io.OrgJsonDeserializer
import io.jsonwebtoken.orgjson.io.OrgJsonSerializer
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.security.Key

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

/**
 * Asserts that serializing and deserializing private or secret key values works as expected without
 * exposing raw strings in the JWKs themselves (should be wrapped with RedactedSupplier instances) for toString safety.
 */
class JwkSerializationTest {

    static String serialize(Serializer ser, def value) {
        def out = new ByteArrayOutputStream()
        ser.serialize(value, out)
        return Strings.utf8(out.toByteArray())
    }

    static Map<String, ?> deserialize(Deserializer des, String value) {
        return des.deserialize(new StringReader(value)) as Map<String, ?>
    }

    @Test
    void testJacksonSecretJwk() {
        testSecretJwk(new JacksonSerializer(), new JacksonDeserializer())
    }

    @Test
    void testJacksonPrivateEcJwk() {
        testPrivateEcJwk(new JacksonSerializer(), new JacksonDeserializer())
    }

    @Test
    void testJacksonPrivateRsaJwk() {
        testPrivateRsaJwk(new JacksonSerializer(), new JacksonDeserializer())
    }

    @Test
    void testGsonSecretJwk() {
        testSecretJwk(new GsonSerializer(), new GsonDeserializer())
    }

    @Test
    void testGsonPrivateEcJwk() {
        testPrivateEcJwk(new GsonSerializer(), new GsonDeserializer())
    }

    @Test
    void testGsonPrivateRsaJwk() {
        testPrivateRsaJwk(new GsonSerializer(), new GsonDeserializer())
    }

    @Test
    void testOrgJsonSecretJwk() {
        testSecretJwk(new OrgJsonSerializer(), new OrgJsonDeserializer())
    }

    @Test
    void testOrgJsonPrivateEcJwk() {
        testPrivateEcJwk(new OrgJsonSerializer(), new OrgJsonDeserializer())
    }

    @Test
    void testOrgJsonPrivateRsaJwk() {
        testPrivateRsaJwk(new OrgJsonSerializer(), new OrgJsonDeserializer())
    }

    static void testSecretJwk(Serializer ser, Deserializer des) {

        def key = TestKeys.NA256
        def jwk = Jwks.builder().key(key).id('id').build()
        assertWrapped(jwk, ['k'])

        // Ensure no Groovy or Java toString prints out secret values:
        assertEquals '[kid:id, kty:oct, k:<redacted>]', "$jwk" as String // groovy gstring
        assertEquals '{kid=id, kty=oct, k=<redacted>}', jwk.toString() // java toString

        //but serialization prints the real value:
        String json = serialize(ser, jwk)
        // assert substrings here because JSON order is not guaranteed:
        assertTrue json.contains('"kid":"id"')
        assertTrue json.contains('"kty":"oct"')
        assertTrue json.contains("\"k\":\"${jwk.k.get()}\"" as String)

        //now ensure it deserializes back to a JWK:
        def map = deserialize(des, json)
        def jwk2 = Jwks.builder().add(map).build()
        assertTrue jwk.k instanceof Supplier
        assertEquals jwk, jwk2
        assertEquals jwk.k, jwk2.k
        assertEquals jwk.k.get(), jwk2.k.get()
    }

    static void testPrivateEcJwk(Serializer ser, Deserializer des) {

        def jwk = Jwks.builder().ecKeyPair(TestKeys.ES256.pair).id('id').build()
        assertWrapped(jwk, ['d'])

        // Ensure no Groovy or Java toString prints out secret values:
        assertEquals '[kid:id, kty:EC, crv:P-256, x:ZWF7HQuzPoW_HarfomiU-HCMELJ486IzskTXL5fwuy4, y:Hf3WL_YAGj1XCSa5HSIAFsItY-SQNjRb1TdKQFEb3oU, d:<redacted>]', "$jwk" as String
        // groovy gstring
        assertEquals '{kid=id, kty=EC, crv=P-256, x=ZWF7HQuzPoW_HarfomiU-HCMELJ486IzskTXL5fwuy4, y=Hf3WL_YAGj1XCSa5HSIAFsItY-SQNjRb1TdKQFEb3oU, d=<redacted>}', jwk.toString()
        // java toString

        //but serialization prints the real value:
        String json = serialize(ser, jwk)
        // assert substrings here because JSON order is not guaranteed:
        assertTrue json.contains('"kid":"id"')
        assertTrue json.contains('"kty":"EC"')
        assertTrue json.contains('"crv":"P-256"')
        assertTrue json.contains('"x":"ZWF7HQuzPoW_HarfomiU-HCMELJ486IzskTXL5fwuy4"')
        assertTrue json.contains('"y":"Hf3WL_YAGj1XCSa5HSIAFsItY-SQNjRb1TdKQFEb3oU"')
        assertTrue json.contains("\"d\":\"${jwk.d.get()}\"" as String)

        //now ensure it deserializes back to a JWK:
        def map = deserialize(des, json)
        def jwk2 = Jwks.builder().add(map).build()
        assertTrue jwk.d instanceof Supplier
        assertEquals jwk, jwk2
        assertEquals jwk.d, jwk2.d
        assertEquals jwk.d.get(), jwk2.d.get()
    }

    private static assertWrapped(Map<String, ?> map, List<String> keys) {
        for (String key : keys) {
            def value = map.get(key)
            assertTrue value instanceof Supplier
            value = ((Supplier<?>) value).get()
            assertTrue value instanceof String
        }
    }

    private static assertEquals(Jwk<? extends Key> jwk1, Jwk<? extends Key> jwk2, List<String> keys) {
        assertEquals jwk1, jwk2
        for (String key : keys) {
            assertTrue jwk1.get(key) instanceof Supplier
            assertTrue jwk2.get(key) instanceof Supplier
            assertEquals jwk1.get(key), jwk2.get(key)
            assertEquals jwk1.get(key).get(), jwk2.get(key).get()
        }
    }

    static void testPrivateRsaJwk(Serializer ser, Deserializer des) {

        def jwk = Jwks.builder().rsaKeyPair(TestKeys.RS256.pair).id('id').build()
        def privateFieldNames = ['d', 'p', 'q', 'dp', 'dq', 'qi']
        assertWrapped(jwk, privateFieldNames)

        // Ensure no Groovy or Java toString prints out secret values:
        assertEquals '[kid:id, kty:RSA, n:vPYf1VSy58i6ic93goenzF5UO9oLxyiTSF64lGFUJ6_MBDydAvY9PS76ymvhUcSrsDUHgb0arsp6MDXOfZxYHn2C7o39n8-bQ7yS4hQm6kkl8KB5OiOkJFkFjEHrwnqykXygx1VFpcVpbBvxDn640ODEScWyoUUPd4sOK-esTt4D9-q0PXsXzfRT4eOrnpXHJTan_KK_a-UYmfWPr-xIEPUxnLPCD68mIHoSPAaJiv37SkAWHJ9-fm_DfnYTwTi0rxe2FRQ1-vkOxe6C2-n1ebsqCZPKr0J_2MfwqP0raxLfyGicxM5ee5RSTTRMCA4UyX5dubZvh2pLoaS8PCZajw, e:AQAB, d:<redacted>, p:<redacted>, q:<redacted>, dp:<redacted>, dq:<redacted>, qi:<redacted>]', "$jwk" as String
        // groovy gstring
        assertEquals '{kid=id, kty=RSA, n=vPYf1VSy58i6ic93goenzF5UO9oLxyiTSF64lGFUJ6_MBDydAvY9PS76ymvhUcSrsDUHgb0arsp6MDXOfZxYHn2C7o39n8-bQ7yS4hQm6kkl8KB5OiOkJFkFjEHrwnqykXygx1VFpcVpbBvxDn640ODEScWyoUUPd4sOK-esTt4D9-q0PXsXzfRT4eOrnpXHJTan_KK_a-UYmfWPr-xIEPUxnLPCD68mIHoSPAaJiv37SkAWHJ9-fm_DfnYTwTi0rxe2FRQ1-vkOxe6C2-n1ebsqCZPKr0J_2MfwqP0raxLfyGicxM5ee5RSTTRMCA4UyX5dubZvh2pLoaS8PCZajw, e=AQAB, d=<redacted>, p=<redacted>, q=<redacted>, dp=<redacted>, dq=<redacted>, qi=<redacted>}', jwk.toString()
        // java toString

        //but serialization prints the real value:
        String json = serialize(ser, jwk)
        // assert substrings here because JSON order is not guaranteed:
        assertTrue json.contains('"kid":"id"')
        assertTrue json.contains('"kty":"RSA"')
        assertTrue json.contains('"e":"AQAB"')
        assertTrue json.contains("\"n\":\"${jwk.n}\"" as String) //public property, not wrapped
        assertTrue json.contains("\"d\":\"${jwk.d.get()}\"" as String) // all remaining should be wrapped
        assertTrue json.contains("\"p\":\"${jwk.p.get()}\"" as String)
        assertTrue json.contains("\"q\":\"${jwk.q.get()}\"" as String)
        assertTrue json.contains("\"dp\":\"${jwk.dp.get()}\"" as String)
        assertTrue json.contains("\"dq\":\"${jwk.dq.get()}\"" as String)
        assertTrue json.contains("\"qi\":\"${jwk.qi.get()}\"" as String)

        //now ensure it deserializes back to a JWK:
        def map = deserialize(des, json)
        def jwk2 = Jwks.builder().add(map).build()
        assertEquals(jwk, jwk2, privateFieldNames)
    }
}
