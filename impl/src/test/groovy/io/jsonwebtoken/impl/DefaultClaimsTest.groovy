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
import io.jsonwebtoken.impl.lang.Parameter
import io.jsonwebtoken.lang.DateFormats
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
                String.format(DefaultClaims.CONVERSION_ERROR_MSG, 'class java.lang.Integer', 'class java.lang.String'),
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
                    String.format(DefaultClaims.CONVERSION_ERROR_MSG, 'class java.lang.Integer', 'class java.lang.Short')
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
                    String.format(DefaultClaims.CONVERSION_ERROR_MSG, 'class java.lang.Integer', 'class java.lang.Short')
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
                    String.format(DefaultClaims.CONVERSION_ERROR_MSG, 'class java.lang.Integer', 'class java.lang.Byte')
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
                    String.format(DefaultClaims.CONVERSION_ERROR_MSG, 'class java.lang.Integer', 'class java.lang.Byte')
            )
        }
    }

    @Test
    void testGetRequiredIntegerFromLong() {
        claims.put('foo', Long.valueOf(Integer.MAX_VALUE))
        assertEquals Integer.MAX_VALUE, claims.get('foo', Integer.class) as Integer
    }

    @Test
    void testGetRequiredIntegerWouldCauseOverflow() {
        claims.put('foo', Long.MAX_VALUE)
        try {
            claims.get('foo', Integer.class)
        } catch (RequiredTypeException expected) {
            String msg = "Claim 'foo' value is too large or too small to be represented as a java.lang.Integer instance (would cause numeric overflow)."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testGetRequiredDateFromNull() {
        Date date = claims.get("aDate", Date.class)
        assertNull date
    }

    @Test
    void testGetRequiredDateFromDate() {
        def expected = new Date()
        claims.put("aDate", expected)
        Date result = claims.get("aDate", Date.class)
        assertEquals expected, result
    }

    @Test
    void testGetRequiredDateFromCalendar() {
        def c = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        def expected = c.getTime()
        claims.put("aDate", c)
        Date result = claims.get('aDate', Date.class)
        assertEquals expected, result
    }

    @Test
    void testGetRequiredDateFromLong() {
        def expected = new Date()
        // note that Long is stored in claim
        claims.put("aDate", expected.getTime())
        Date result = claims.get("aDate", Date.class)
        assertEquals expected, result
    }

    @Test
    void testGetRequiredDateFromIso8601String() {
        def expected = new Date()
        claims.put("aDate", DateFormats.formatIso8601(expected))
        Date result = claims.get("aDate", Date.class)
        assertEquals expected, result
    }

    @Test
    void testGetRequiredDateFromIso8601MillisString() {
        def expected = new Date()
        claims.put("aDate", DateFormats.formatIso8601(expected, true))
        Date result = claims.get("aDate", Date.class)
        assertEquals expected, result
    }

    @Test
    void testGetRequiredDateFromInvalidIso8601String() {
        Date d = new Date()
        String s = d.toString()
        claims.put('aDate', s)
        try {
            claims.get('aDate', Date.class)
            fail()
        } catch (IllegalArgumentException expected) {
            String expectedMsg = "Cannot create Date from 'aDate' value '$s'. Cause: " +
                    "String value is not a JWT NumericDate, nor is it ISO-8601-formatted. All heuristics " +
                    "exhausted. Cause: Unparseable date: \"$s\""
            assertEquals expectedMsg, expected.getMessage()
        }
    }

    @Test
    void testToSpecDateWithNull() {
        assertNull claims.get(Claims.EXPIRATION)
        assertNull claims.getExpiration()
        assertNull claims.get(Claims.ISSUED_AT)
        assertNull claims.getIssuedAt()
        assertNull claims.get(Claims.NOT_BEFORE)
        assertNull claims.getNotBefore()
    }

    @Test
    void testGetSpecDateWithLongString() {
        Date orig = new Date()
        long millis = orig.getTime()
        long seconds = millis / 1000L as long
        Date expected = new Date(seconds * 1000L)
        String secondsString = '' + seconds
        claims.put(Claims.EXPIRATION, secondsString)
        claims.put(Claims.ISSUED_AT, secondsString)
        claims.put(Claims.NOT_BEFORE, secondsString)
        assertEquals expected, claims.getExpiration()
        assertEquals expected, claims.getIssuedAt()
        assertEquals expected, claims.getNotBefore()
        assertEquals seconds, claims.get(Claims.EXPIRATION)
        assertEquals seconds, claims.get(Claims.ISSUED_AT)
        assertEquals seconds, claims.get(Claims.NOT_BEFORE)
    }

    @Test
    void testGetSpecDateWithLong() {
        Date orig = new Date()
        long millis = orig.getTime()
        long seconds = millis / 1000L as long
        Date expected = new Date(seconds * 1000L)
        claims.put(Claims.EXPIRATION, seconds)
        claims.put(Claims.ISSUED_AT, seconds)
        claims.put(Claims.NOT_BEFORE, seconds)
        assertEquals expected, claims.getExpiration()
        assertEquals expected, claims.getIssuedAt()
        assertEquals expected, claims.getNotBefore()
        assertEquals seconds, claims.get(Claims.EXPIRATION)
        assertEquals seconds, claims.get(Claims.ISSUED_AT)
        assertEquals seconds, claims.get(Claims.NOT_BEFORE)
    }

    @Test
    void testGetSpecDateWithIso8601String() {
        Date orig = new Date()
        long millis = orig.getTime()
        long seconds = millis / 1000L as long
        String s = DateFormats.formatIso8601(orig)
        claims.put(Claims.EXPIRATION, s)
        claims.put(Claims.ISSUED_AT, s)
        claims.put(Claims.NOT_BEFORE, s)
        assertEquals orig, claims.getExpiration()
        assertEquals orig, claims.getIssuedAt()
        assertEquals orig, claims.getNotBefore()
        assertEquals seconds, claims.get(Claims.EXPIRATION)
        assertEquals seconds, claims.get(Claims.ISSUED_AT)
        assertEquals seconds, claims.get(Claims.NOT_BEFORE)
    }

    @Test
    void testGetSpecDateWithDate() {
        Date orig = new Date()
        long millis = orig.getTime()
        long seconds = millis / 1000L as long
        claims.put(Claims.EXPIRATION, orig)
        claims.put(Claims.ISSUED_AT, orig)
        claims.put(Claims.NOT_BEFORE, orig)
        assertEquals orig, claims.getExpiration()
        assertEquals orig, claims.getIssuedAt()
        assertEquals orig, claims.getNotBefore()
        assertEquals seconds, claims.get(Claims.EXPIRATION)
        assertEquals seconds, claims.get(Claims.ISSUED_AT)
        assertEquals seconds, claims.get(Claims.NOT_BEFORE)
    }

    @Test
    void testGetSpecDateWithCalendar() {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        Date date = cal.getTime()
        long millis = date.getTime()
        long seconds = millis / 1000L as long
        claims.put(Claims.EXPIRATION, cal)
        claims.put(Claims.ISSUED_AT, cal)
        claims.put(Claims.NOT_BEFORE, cal)
        assertEquals date, claims.getExpiration()
        assertEquals date, claims.getIssuedAt()
        assertEquals date, claims.getNotBefore()
        assertEquals seconds, claims.get(Claims.EXPIRATION)
        assertEquals seconds, claims.get(Claims.ISSUED_AT)
        assertEquals seconds, claims.get(Claims.NOT_BEFORE)
    }

    @Test
    void testToSpecDateWithDate() {
        long millis = System.currentTimeMillis()
        Date d = new Date(millis)
        claims.put('exp', d)
        assertEquals d, claims.getExpiration()
    }

    void trySpecDateNonDate(Parameter<?> param) {
        def val = new Object() { @Override String toString() {return 'hi'} }
        try {
            claims.put(param.getId(), val)
            fail()
        } catch (IllegalArgumentException iae) {
            String msg = "Invalid JWT Claim $param value: hi. Cannot create Date from object of type io.jsonwebtoken.impl.DefaultClaimsTest\$1."
            assertEquals msg, iae.getMessage()
        }
    }

    @Test
    void testSpecDateFromNonDateObject() {
        trySpecDateNonDate(DefaultClaims.EXPIRATION)
        trySpecDateNonDate(DefaultClaims.ISSUED_AT)
        trySpecDateNonDate(DefaultClaims.NOT_BEFORE)
    }

    @Test
    void testGetClaimExpiration_Success() {
        def now = new Date(System.currentTimeMillis())
        claims.put('exp', now)
        Date expected = claims.get("exp", Date.class)
        assertEquals(expected, claims.getExpiration())
    }

    @Test
    void testGetClaimIssuedAt_Success() {
        def now = new Date(System.currentTimeMillis())
        claims.put('iat', now)
        Date expected = claims.get("iat", Date.class)
        assertEquals(expected, claims.getIssuedAt())
    }

    @Test
    void testGetClaimNotBefore_Success() {
        def now = new Date(System.currentTimeMillis())
        claims.put('nbf', now)
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

}
