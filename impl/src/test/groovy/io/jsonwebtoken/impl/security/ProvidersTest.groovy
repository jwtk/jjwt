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

import io.jsonwebtoken.lang.Classes
import org.junit.After
import org.junit.Before
import org.junit.Test

import java.security.Provider
import java.security.Security

import static org.junit.Assert.*

class ProvidersTest {

    @Before
    void before() {
        cleanup() // ensure we start clean
    }

    @After
    void after() {
        cleanup() // ensure we end clean
    }

    static void cleanup() {
        //ensure test environment is cleaned up:
        Providers.BC_PROVIDER.set(null)
        Security.removeProvider("BC")
        assertFalse bcRegistered() // ensure clean
    }

    static boolean bcRegistered() {
        for (Provider p : Security.getProviders()) {
            // do not reference the Providers class constant here - this is a utility method that could be used in
            // other test classes that use static mocks and the `Provider` class might not be able to initialized
            if (p.getClass().getName().equals("org.bouncycastle.jce.provider.BouncyCastleProvider")) {
                return true
            }
        }
        return false
    }

    @Test
    void testPrivateCtor() { // for code coverage only
        new Providers()
    }

    @Test
    void testBouncyCastleAlreadyExists() {

        // ensure we don't have one yet:
        assertNull Providers.BC_PROVIDER.get()
        assertFalse bcRegistered()

        //now register one in the JVM provider list:
        Provider bc = Classes.newInstance(Providers.BC_PROVIDER_CLASS_NAME)
        assertEquals "BC", bc.getName()
        Security.addProvider(bc)
        assertTrue bcRegistered() // ensure it exists in the system as expected

        //now ensure that we find it and cache it:
        def returned = Providers.findBouncyCastle()
        assertSame bc, returned
        assertSame bc, Providers.BC_PROVIDER.get() // ensure cached for future lookup

        //ensure cache hit works:
        assertSame bc, Providers.findBouncyCastle()

        //cleanup() method will remove the provider from the system
    }

    @Test
    void testBouncyCastleCreatedIfAvailable() {
        // ensure we don't have one yet:
        assertNull Providers.BC_PROVIDER.get()
        assertFalse bcRegistered()

        // ensure we can create one and cache it, *without* modifying the system JVM:
        //now ensure that we find it and cache it:
        def returned = Providers.findBouncyCastle()
        assertNotNull returned
        assertSame Providers.BC_PROVIDER.get(), returned //ensure cached for future lookup
        assertFalse bcRegistered() //ensure we don't alter the system environment

        assertSame returned, Providers.findBouncyCastle() //ensure cache hit
        assertFalse bcRegistered() //ensure we don't alter the system environment
    }
}
