package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import javax.crypto.KeyGenerator
import java.security.NoSuchAlgorithmException

import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.junit.Assert.*
import static org.powermock.api.easymock.PowerMock.*

/**
 * This needs to be a separate class beyond MacProviderTest because it mocks the KeyGenerator class which messes up
 * the other implementation tests in MacProviderTest.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest([KeyGenerator])
class PowermockMacProviderTest {

    @Test
    void testNoSuchAlgorithm() {

        mockStatic(KeyGenerator)

        def alg = SignatureAlgorithm.HS256
        def ex = new NoSuchAlgorithmException('foo')

        expect(KeyGenerator.getInstance(eq(alg.jcaName))).andThrow(ex)

        replay KeyGenerator

        try {
            MacProvider.generateKey(alg)
            fail()
        } catch (IllegalStateException e) {
            assertEquals 'The HmacSHA256 algorithm is not available.  This should never happen on JDK 7 or later - ' +
                    'please report this to the JJWT developers.', e.message
            assertSame ex, e.getCause()
        }

        verify KeyGenerator

        reset KeyGenerator
    }
}
