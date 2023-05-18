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

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertTrue

class KeyUsageTest {

    private static KeyUsage usage(int trueIndex) {
        boolean[] usage = new boolean[9]
        usage[trueIndex] = true
        return new KeyUsage(new TestX509Certificate(keyUsage: usage))
    }

    private KeyUsage ku

    @Before
    void setUp() {
        ku = new KeyUsage(new TestX509Certificate())
    }

    @Test
    void testNullCert() {
        ku = new KeyUsage(null)
        assertFalse ku.isCRLSign()
        assertFalse ku.isDataEncipherment()
        assertFalse ku.isDecipherOnly()
        assertFalse ku.isDigitalSignature()
        assertFalse ku.isEncipherOnly()
        assertFalse ku.isKeyAgreement()
        assertFalse ku.isKeyCertSign()
        assertFalse ku.isKeyEncipherment()
        assertFalse ku.isNonRepudiation()
    }

    @Test
    void testCertWithNullKeyUsage() {
        ku = new KeyUsage(new TestX509Certificate(keyUsage: null))
        assertFalse ku.isCRLSign()
        assertFalse ku.isDataEncipherment()
        assertFalse ku.isDecipherOnly()
        assertFalse ku.isDigitalSignature()
        assertFalse ku.isEncipherOnly()
        assertFalse ku.isKeyAgreement()
        assertFalse ku.isKeyCertSign()
        assertFalse ku.isKeyEncipherment()
        assertFalse ku.isNonRepudiation()
    }

    @Test
    void testDigitalSignature() {
        assertFalse ku.isDigitalSignature() //default
        assertTrue usage(0).isDigitalSignature()
    }

    @Test
    void testNonRepudiation() {
        assertFalse ku.isNonRepudiation()
        assertTrue usage(1).isNonRepudiation()
    }

    @Test
    void testKeyEncipherment() {
        assertFalse ku.isKeyEncipherment()
        assertTrue usage(2).isKeyEncipherment()
    }

    @Test
    void testDataEncipherment() {
        assertFalse ku.isDataEncipherment()
        assertTrue usage(3).isDataEncipherment()
    }

    @Test
    void testKeyAgreement() {
        assertFalse ku.isKeyAgreement()
        assertTrue usage(4).isKeyAgreement()
    }

    @Test
    void testKeyCertSign() {
        assertFalse ku.isKeyCertSign()
        assertTrue usage(5).isKeyCertSign()
    }

    @Test
    void testCRLSign() {
        assertFalse ku.isCRLSign()
        assertTrue usage(6).isCRLSign()
    }

    @Test
    void testEncipherOnly() {
        assertFalse ku.isEncipherOnly()
        assertTrue usage(7).isEncipherOnly()
    }

    @Test
    void testDecipherOnly() {
        assertFalse ku.isDecipherOnly()
        assertTrue usage(8).isDecipherOnly()
    }
}
