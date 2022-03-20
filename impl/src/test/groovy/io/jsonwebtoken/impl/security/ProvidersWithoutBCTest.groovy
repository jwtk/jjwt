package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Conditions
import io.jsonwebtoken.lang.Classes
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertNull
import static org.powermock.api.easymock.PowerMock.*

@RunWith(PowerMockRunner.class)
@PrepareForTest([Classes])
class ProvidersWithoutBCTest {

    @After
    void after() {
        ProvidersTest.cleanup() //ensure environment is clean
    }

    @Test
    void testBouncyCastleClassNotAvailable() {
        mockStatic(Classes)
        expect(Classes.isAvailable(eq("org.bouncycastle.jce.provider.BouncyCastleProvider"))).andReturn(Boolean.FALSE).anyTimes()
        replay Classes
        assertNull Providers.getBouncyCastle(Conditions.TRUE) // one should not be created/exist
        verify Classes
        assertFalse ProvidersTest.bcRegistered() // nothing should be in the environment
    }
}
