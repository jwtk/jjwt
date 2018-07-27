package io.jsonwebtoken.security

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.lang.Classes
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import javax.crypto.SecretKey
import java.security.KeyPair

import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.same
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.*

/**
 * This test class is for cursory API-level testing only (what is available to the API module at build time).
 *
 * The actual implementation assertions are done in KeysImplTest in the impl module.
 */
@RunWith(PowerMockRunner)
@PrepareForTest([Classes, Keys])
class KeysTest {

    @Test
    void testPrivateCtor() { //for code coverage only
        new Keys()
    }

    @Test
    void testSecretKeyFor() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (name.startsWith('H')) {

                mockStatic(Classes)

                def key = createMock(SecretKey)
                expect(Classes.invokeStatic(eq(Keys.MAC), eq("generateKey"), same(Keys.SIG_ARG_TYPES), same(alg))).andReturn(key)

                replay Classes, key

                assertSame key, Keys.secretKeyFor(alg)

                verify Classes, key

                reset Classes, key

            } else {
                try {
                    Keys.secretKeyFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support shared secret keys." as String, expected.message
                }

            }
        }

    }

    @Test
    void testKeyPairFor() {

        for (SignatureAlgorithm alg : SignatureAlgorithm.values()) {

            String name = alg.name()

            if (name.equals('NONE') || name.startsWith('H')) {
                try {
                    Keys.keyPairFor(alg)
                    fail()
                } catch (IllegalArgumentException expected) {
                    assertEquals "The $name algorithm does not support Key Pairs." as String, expected.message
                }
            } else {
                String fqcn = name.startsWith('E') ? Keys.EC : Keys.RSA

                mockStatic Classes

                def pair = createMock(KeyPair)
                expect(Classes.invokeStatic(eq(fqcn), eq("generateKeyPair"), same(Keys.SIG_ARG_TYPES), same(alg))).andReturn(pair)

                replay Classes, pair

                assertSame pair, Keys.keyPairFor(alg)

                verify Classes, pair

                reset Classes, pair
            }
        }
    }
}
