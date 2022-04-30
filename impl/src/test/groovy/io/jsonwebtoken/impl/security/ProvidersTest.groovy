package io.jsonwebtoken.impl.security


import io.jsonwebtoken.impl.lang.Conditions
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
        def returned = Providers.findBouncyCastle(Conditions.TRUE)
        assertSame bc, returned
        assertSame bc, Providers.BC_PROVIDER.get() // ensure cached for future lookup

        //cleanup() method will remove the provider from the system
    }

    @Test
    void testBouncyCastleCreatedIfAvailable() {
        // ensure we don't have one yet:
        assertNull Providers.BC_PROVIDER.get()
        assertFalse bcRegistered()

        // ensure we can create one and cache it, *without* modifying the system JVM:
        //now ensure that we find it and cache it:
        def returned = Providers.findBouncyCastle(Conditions.TRUE)
        assertNotNull returned
        assertSame Providers.BC_PROVIDER.get(), returned //ensure cached for future lookup
        assertFalse bcRegistered() //ensure we don't alter the system environment
    }
}
