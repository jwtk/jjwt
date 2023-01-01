/*
 * Copyright (C) 2020 jsonwebtoken.io
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

import io.jsonwebtoken.security.Request
import org.junit.Test

import java.security.Provider

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class CryptoAlgorithmTest {

    @Test
    void testEqualsSameInstance() {
        def alg = new TestCryptoAlgorithm('test', 'test')
        assertEquals alg, alg
    }

    @Test
    void testEqualsSameNameAndJcaName() {
        def alg1 = new TestCryptoAlgorithm('test', 'test')
        def alg2 = new TestCryptoAlgorithm('test', 'test')
        assertEquals alg1, alg2
    }

    @Test
    void testEqualsSameNameButDifferentJcaName() {
        def alg1 = new TestCryptoAlgorithm('test', 'test1')
        def alg2 = new TestCryptoAlgorithm('test', 'test2')
        assertNotEquals alg1, alg2
    }

    @Test
    void testEqualsOtherType() {
        assertNotEquals new TestCryptoAlgorithm('test', 'test'), new Object()
    }

    @Test
    void testToString() {
        assertEquals 'test', new TestCryptoAlgorithm('test', 'whatever').toString()
    }

    @Test
    void testHashCode() {
        int hash = 7
        hash = 31 * hash + 'name'.hashCode()
        hash = 31 * hash + 'jcaName'.hashCode()
        assertEquals hash, new TestCryptoAlgorithm('name', 'jcaName').hashCode()
    }

    @Test
    void testEnsureSecureRandomWorksWithNullRequest() {
        def alg = new TestCryptoAlgorithm('test', 'test')
        def random = alg.ensureSecureRandom(null)
        assertSame Randoms.secureRandom(), random
    }

    @Test
    void testRequestProviderPriorityOverDefaultProvider() {

        def alg = new TestCryptoAlgorithm('test', 'test')

        Provider defaultProvider = createMock(Provider)
        Provider requestProvider = createMock(Provider)
        Request request = createMock(Request)
        alg.setProvider(defaultProvider)

        expect(request.getProvider()).andReturn(requestProvider)

        replay request, requestProvider, defaultProvider

        assertSame requestProvider, alg.getProvider(request) // assert we get back the request provider, not the default

        verify request, requestProvider, defaultProvider
    }

    @Test
    void testMissingRequestProviderUsesDefaultProvider() {

        def alg = new TestCryptoAlgorithm('test', 'test')

        Provider defaultProvider = createMock(Provider)
        Request request = createMock(Request)
        alg.setProvider(defaultProvider)

        expect(request.getProvider()).andReturn(null)

        replay request, defaultProvider

        assertSame defaultProvider, alg.getProvider(request) // assert we get back the default provider

        verify request, defaultProvider
    }

    @Test
    void testMissingRequestAndDefaultProviderReturnsNull() {
        def alg = new TestCryptoAlgorithm('test', 'test')
        Request request = createMock(Request)
        expect(request.getProvider()).andReturn(null)
        replay request
        assertNull alg.getProvider(request) // null return value means use JCA internal default provider
        verify request
    }


    class TestCryptoAlgorithm extends CryptoAlgorithm {
        TestCryptoAlgorithm(String id, String jcaName) {
            super(id, jcaName)
        }
    }
}
