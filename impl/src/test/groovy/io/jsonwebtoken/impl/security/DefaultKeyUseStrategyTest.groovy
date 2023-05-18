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

import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNull

class DefaultKeyUseStrategyTest {

    final KeyUseStrategy strat = DefaultKeyUseStrategy.INSTANCE

    private static KeyUsage usage(int trueIndex) {
        boolean[] usage = new boolean[9]
        usage[trueIndex] = true
        return new KeyUsage(new TestX509Certificate(keyUsage: usage))
    }

    @Test
    void testKeyEncipherment() {
        assertEquals 'enc', strat.toJwkValue(usage(2))
    }

    @Test
    void testDataEncipherment() {
        assertEquals 'enc', strat.toJwkValue(usage(3))
    }

    @Test
    void testKeyAgreement() {
        assertEquals 'enc', strat.toJwkValue(usage(4))
    }

    @Test
    void testDigitalSignature() {
        assertEquals 'sig', strat.toJwkValue(usage(0))
    }

    @Test
    void testNonRepudiation() {
        assertEquals 'sig', strat.toJwkValue(usage(1))
    }

    @Test
    void testKeyCertSign() {
        assertEquals 'sig', strat.toJwkValue(usage(5))
    }

    @Test
    void testCRLSign() {
        assertEquals 'sig', strat.toJwkValue(usage(6))
    }

    @Test
    void testEncipherOnly() {
        assertNull strat.toJwkValue(usage(7))
    }

    @Test
    void testDecipherOnly() {
        assertNull strat.toJwkValue(usage(8))
    }
}
