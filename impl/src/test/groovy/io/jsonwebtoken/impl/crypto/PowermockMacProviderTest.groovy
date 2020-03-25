/*
 * Copyright (C) 2014 jsonwebtoken.io
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
