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
    void testGetClaimWithRequiredType_Success() {
        claims.put("anInteger", new Integer(5))
        Object result = claims.get("anInteger", Integer.class)

        assertTrue(result instanceof Integer)
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

}
