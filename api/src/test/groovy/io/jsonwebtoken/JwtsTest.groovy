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
package io.jsonwebtoken

import io.jsonwebtoken.lang.Services
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.mock
import static org.easymock.EasyMock.reset
import static org.easymock.EasyMock.same
import static org.junit.Assert.assertSame
import static org.powermock.api.easymock.PowerMock.createMock
import static org.powermock.api.easymock.PowerMock.mockStatic
import static org.powermock.api.easymock.PowerMock.replay
import static org.powermock.api.easymock.PowerMock.verify

@RunWith(PowerMockRunner.class)
@PrepareForTest([Services])
class JwtsTest {

    static JwtFactory factory = mock(JwtFactory)

    @BeforeClass
    static void prepareFactory() {
        mockStatic(Services)

        expect(Services.loadFirst(JwtFactory)).andReturn(factory).anyTimes()

        replay Services
    }

    @Before
    void resetFactoryMock() {
        reset(factory)
    }

    @Test
    void testPrivateCtor() { //for code coverage only
        new Jwts()
    }

    @Test
    void testHeader() {

        def instance = createMock(Header)

        expect(factory.header()).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.header()

        verify factory, instance
    }

    @Test
    void testHeaderFromMap() {

        def map = [:]

        def instance = createMock(Header)

        expect(factory.header(same(map) as Map<String, Object>)).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.header(map)

        verify factory, instance
    }

    @Test
    void testJwsHeader() {

        def instance = createMock(JwsHeader)

        expect(factory.jwsHeader()).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.jwsHeader()

        verify factory, instance
    }

    @Test
    void testJwsHeaderFromMap() {

        def map = [:]

        def instance = createMock(JwsHeader)

        expect(factory.jwsHeader(same(map) as Map<String, Object>)).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.jwsHeader(map)

        verify factory, instance
    }

    @Test
    void testClaims() {

        def instance = createMock(Claims)

        expect(factory.claims()).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.claims()

        verify factory, instance
    }

    @Test
    void testClaimsFromMap() {

        def map = [:]

        def instance = createMock(Claims)

        expect(factory.claims(same(map) as Map<String, Object>)).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.claims(map)

        verify factory, instance
    }

    @Test
    void testParser() {

        def instance = createMock(JwtParser)

        expect(factory.parser()).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.parser()

        verify factory, instance
    }

    @Test
    void testBuilder() {

        def instance = createMock(JwtBuilder)

        expect(factory.builder()).andReturn(instance)

        replay factory, instance

        assertSame instance, Jwts.builder()

        verify factory, instance
    }
}
