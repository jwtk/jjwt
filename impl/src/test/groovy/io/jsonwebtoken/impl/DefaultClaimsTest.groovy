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
package io.jsonwebtoken.impl

import io.jsonwebtoken.Claims
import io.jsonwebtoken.RequiredTypeException
import org.apache.groovy.util.Maps
import org.junit.Before
import org.junit.Test
import static org.junit.Assert.*

class DefaultClaimsTest {

    Claims claims

    @Before
    void setup() {
        claims = new DefaultClaims()
    }

    @Test
    void testGetClaimWithRequiredType_Null_Success() {
        claims.put("aNull", null)
        Object result = claims.get("aNull", Integer.class)
        assertNull(result)
    }

    @Test
    void testGetClaimWithRequiredType_Exception() {
        claims.put("anInteger", new Integer(5))
        try {
            claims.get("anInteger", String.class)
            fail()
        } catch (RequiredTypeException e) {
            assertEquals(
                "Expected value to be of type: class java.lang.String, but was class java.lang.Integer",
                e.getMessage()
            )
        }
    }

    @Test
    void testGetClaimWithRequiredType_Integer_Success() {
        def expected = new Integer(5)
        claims.put("anInteger", expected)
        Object result = claims.get("anInteger", Integer.class)
        assertEquals(expected, result)
    }

    @Test
    void testGetClaimWithRequiredType_Long_Success() {
        def expected = new Long(123)
        claims.put("aLong", expected)
        Object result = claims.get("aLong", Long.class)
        assertEquals(expected, result)
    }

    @Test
    void testGetClaimWithRequiredType_LongWithInteger_Success() {
        // long value that fits inside an Integer
        def expected = new Long(Integer.MAX_VALUE - 100)
        // deserialized as an Integer from JSON
        // (type information is not available during parsing)
        claims.put("smallLong", expected.intValue())
        // should still be available as Long
        Object result = claims.get("smallLong", Long.class)
        assertEquals(expected, result)
    }

    @Test
    void testGetClaimWithRequiredType_ShortWithInteger_Success() {
        def expected = new Short((short) 42)
        claims.put("short", expected.intValue())
        Object result = claims.get("short", Short.class)
        assertEquals(expected, result)
    }

    @Test
    void testGetClaimWithRequiredType_ShortWithBigInteger_Exception() {
        claims.put("tooBigForShort", ((int) Short.MAX_VALUE) + 42)
        try {
            claims.get("tooBigForShort", Short.class)
            fail("getClaim() shouldn't silently lose precision.")
        } catch (RequiredTypeException e) {
            assertEquals(
                    e.getMessage(),
                    "Expected value to be of type: class java.lang.Short, but was class java.lang.Integer"
            )
        }
    }

    @Test
    void testGetClaimWithRequiredType_ShortWithSmallInteger_Exception() {
        claims.put("tooSmallForShort", ((int) Short.MIN_VALUE) - 42)
        try {
            claims.get("tooSmallForShort", Short.class)
            fail("getClaim() shouldn't silently lose precision.")
        } catch (RequiredTypeException e) {
            assertEquals(
                    e.getMessage(),
                    "Expected value to be of type: class java.lang.Short, but was class java.lang.Integer"
            )
        }
    }

    @Test
    void testGetClaimWithRequiredType_ByteWithInteger_Success() {
        def expected = new Byte((byte) 42)
        claims.put("byte", expected.intValue())
        Object result = claims.get("byte", Byte.class)
        assertEquals(expected, result)
    }

    @Test
    void testGetClaimWithRequiredType_ByteWithBigInteger_Exception() {
        claims.put("tooBigForByte", ((int) Byte.MAX_VALUE) + 42)
        try {
            claims.get("tooBigForByte", Byte.class)
            fail("getClaim() shouldn't silently lose precision.")
        } catch (RequiredTypeException e) {
            assertEquals(
                    e.getMessage(),
                    "Expected value to be of type: class java.lang.Byte, but was class java.lang.Integer"
            )
        }
    }

    @Test
    void testGetClaimWithRequiredType_ByteWithSmallInteger_Exception() {
        claims.put("tooSmallForByte", ((int) Byte.MIN_VALUE) - 42)
        try {
            claims.get("tooSmallForByte", Byte.class)
            fail("getClaim() shouldn't silently lose precision.")
        } catch (RequiredTypeException e) {
            assertEquals(
                    e.getMessage(),
                    "Expected value to be of type: class java.lang.Byte, but was class java.lang.Integer"
            )
        }
    }

    @Test
    void testGetClaimWithRequiredType_Date_Success() {
        def actual = new Date();
        claims.put("aDate", actual)
        Date expected = claims.get("aDate", Date.class);
        assertEquals(expected, actual)
    }

    @Test
    void testGetClaimWithRequiredType_DateWithLong_Success() {
        def actual = new Date();
        // note that Long is stored in claim
        claims.put("aDate", actual.getTime())
        Date expected = claims.get("aDate", Date.class);
        assertEquals(expected, actual)
    }

    @Test
    void testGetClaimExpiration_Success() {
        def now = new Date(System.currentTimeMillis())
        claims.setExpiration(now)
        Date expected = claims.get("exp", Date.class)
        assertEquals(expected, claims.getExpiration())
    }

    @Test
    void testGetClaimIssuedAt_Success() {
        def now = new Date(System.currentTimeMillis())
        claims.setIssuedAt(now)
        Date expected = claims.get("iat", Date.class)
        assertEquals(expected, claims.getIssuedAt())
    }

    @Test
    void testGetClaimNotBefore_Success() {
        def now = new Date(System.currentTimeMillis())
        claims.setNotBefore(now)
        Date expected = claims.get("nbf", Date.class)
        assertEquals(expected, claims.getNotBefore())
    }

    @Test
    void testPutWithIat() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        claims.put('iat', now) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('iat') //conversion should have happened
    }

    @Test
    void testPutAllWithIat() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        claims.putAll([iat: now]) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('iat') //conversion should have happened
    }

    @Test
    void testConstructorWithIat() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        this.claims = new DefaultClaims([iat: now]) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('iat') //conversion should have happened
    }

    @Test
    void testPutWithNbf() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        claims.put('nbf', now) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('nbf') //conversion should have happened
    }

    @Test
    void testPutAllWithNbf() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        claims.putAll([nbf: now]) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('nbf') //conversion should have happened
    }

    @Test
    void testConstructorWithNbf() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        this.claims = new DefaultClaims([nbf: now]) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('nbf') //conversion should have happened
    }

    @Test
    void testPutWithExp() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        claims.put('exp', now) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('exp') //conversion should have happened
    }

    @Test
    void testPutAllWithExp() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        claims.putAll([exp: now]) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('exp') //conversion should have happened
    }

    @Test
    void testConstructorWithExp() {
        long millis = System.currentTimeMillis()
        long seconds = millis / 1000 as long
        Date now = new Date(millis)
        this.claims = new DefaultClaims([exp: now]) //this should convert 'now' to seconds since epoch
        assertEquals seconds, claims.get('exp') //conversion should have happened
    }

    @Test
    void testPutWithNonSpecDate() {
        long millis = System.currentTimeMillis()
        Date now = new Date(millis)
        claims.put('foo', now)
        assertEquals now, claims.get('foo') //conversion should NOT have occurred
    }

    @Test
    void testGetClaimAsString() {
        def claimName = "aString"
        def expected = "The quick brown fox jumps over the lazy dog"

        claims.put(claimName, expected)
        String result = claims.getAsString(claimName)

        assertEquals expected, result
    }

    @Test
    void testGetClaimAsInt() {
        def claimName = "anInt"
        def expected = 4_8_15_16_23

        claims.put(claimName, expected)
        Integer result = claims.getAsInt(claimName)

        assertEquals expected, result
    }

    @Test
    void testGetClaimAsLong() {
        def claimName = "aLong"
        def expected = 4_8_15_16_23_42L

        claims.put(claimName, expected)
        Long result = claims.getAsLong(claimName)

        assertEquals expected, result
    }

    @Test
    void testGetClaimAsShort() {
        def claimName = "aShort"
        def expected = 4_8_15

        claims.put(claimName, expected)
        Short result = claims.getAsShort(claimName)

        assertEquals expected, result
    }

    @Test
    void testGetClaimAsByte() {
        def claimName = "aByte"
        def expected = 4_8

        claims.put(claimName, expected)
        Byte result = claims.getAsByte(claimName)

        assertEquals expected, result
    }

    @Test
    void testGetClaimAsDate() {
        def claimName = "aDate"
        def expected = new Date()

        claims.put(claimName, expected)
        Date result = claims.getAsDate(claimName)

        assertEquals expected, result
    }

    @Test
    void testGetClaimAsBoolean() {
        def claimName = "aBoolean"
        def expected = true

        claims.put(claimName, expected)
        Boolean result = claims.getAsBoolean(claimName)

        assertEquals expected, result
    }

    @Test
    void testGetClaimAsMap() {
        def claimName = "aBoolean"
        def expected = Maps.of(
                "key1", 4_8_15_16_23_42L,
                "key2", "abcd",
                "key3", true,
                "key4", new Date()
        )

        claims.put(claimName, expected)
        Map<String, ?> result = claims.getAsMap(claimName)

        assertEquals expected, result
    }
}
