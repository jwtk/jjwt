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

import io.jsonwebtoken.security.MalformedKeyException
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class RSAOtherPrimeInfoConverterTest {

    @Test
    void testApplyFromNull() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom(null)
            fail()
        } catch (MalformedKeyException expected) {
            String msg = 'RSA JWK \'oth\' (Other Prime Info) element cannot be null.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testApplyFromWithoutMap() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom(42)
            fail()
        } catch (MalformedKeyException expected) {
            String msg = 'RSA JWK \'oth\' (Other Prime Info) must contain map elements of ' +
                    'name/value pairs. Element type found: java.lang.Integer'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testApplyFromWithEmptyMap() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom([:])
            fail()
        } catch (MalformedKeyException expected) {
            String msg = 'RSA JWK \'oth\' (Other Prime Info) element map cannot be empty.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testApplyFromWithMalformedMap() {
        try {
            RSAOtherPrimeInfoConverter.INSTANCE.applyFrom(['r':2])
            fail()
        } catch (MalformedKeyException expected) {
            String msg = "Invalid JWK 'r' (Prime Factor) value: <redacted>. Values must be either String or " +
                    "java.math.BigInteger instances. Value type found: java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }
}
