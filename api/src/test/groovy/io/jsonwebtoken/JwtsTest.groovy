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

import io.jsonwebtoken.lang.Classes
import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.easymock.EasyMock.createMock
import static org.easymock.EasyMock.eq
import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.same
import static org.junit.Assert.assertSame
import static org.powermock.api.easymock.PowerMock.mockStatic
import static org.powermock.api.easymock.PowerMock.replay
import static org.powermock.api.easymock.PowerMock.reset
import static org.powermock.api.easymock.PowerMock.verify

@RunWith(PowerMockRunner.class)
@PrepareForTest([Classes, Jwts])
class JwtsTest {

    @Test
    void testPrivateCtor() { //for code coverage only
        new Jwts()
    }

    @Test
    void testHeader() {

        mockStatic(Classes)

        def instance = createMock(Header)

        expect(Classes.newInstance(eq("io.jsonwebtoken.impl.DefaultHeader"))).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.header()

        verify Classes, instance
    }

    @Test
    void testHeaderFromMap() {

        mockStatic(Classes)

        def map = [:]

        def instance = createMock(Header)

        expect(Classes.newInstance(
                eq("io.jsonwebtoken.impl.DefaultHeader"),
                same(Jwts.MAP_ARG),
                same(map))
        ).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.header(map)

        verify Classes, instance
    }

    @Test
    void testJwsHeader() {

        mockStatic(Classes)

        def instance = createMock(JwsHeader)

        expect(Classes.newInstance(eq("io.jsonwebtoken.impl.DefaultJwsHeader"))).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.jwsHeader()

        verify Classes, instance
    }

    @Test
    void testJwsHeaderFromMap() {

        mockStatic(Classes)

        def map = [:]

        def instance = createMock(JwsHeader)

        expect(Classes.newInstance(
                eq("io.jsonwebtoken.impl.DefaultJwsHeader"),
                same(Jwts.MAP_ARG),
                same(map))
        ).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.jwsHeader(map)

        verify Classes, instance
    }

    @Test
    void testClaims() {

        mockStatic(Classes)

        def instance = createMock(Claims)

        expect(Classes.newInstance(eq("io.jsonwebtoken.impl.DefaultClaims"))).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.claims()

        verify Classes, instance
    }

    @Test
    void testClaimsFromMap() {

        mockStatic(Classes)

        def map = [:]

        def instance = createMock(Claims)

        expect(Classes.newInstance(
                eq("io.jsonwebtoken.impl.DefaultClaims"),
                same(Jwts.MAP_ARG),
                same(map))
        ).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.claims(map)

        verify Classes, instance
    }

    @Test
    void testParser() {

        mockStatic(Classes)

        def instance = createMock(JwtParser)

        expect(Classes.newInstance(eq("io.jsonwebtoken.impl.DefaultJwtParser"))).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.parser()

        verify Classes, instance
    }

    @Test
    void testBuilder() {

        mockStatic(Classes)

        def instance = createMock(JwtBuilder)

        expect(Classes.newInstance(eq("io.jsonwebtoken.impl.DefaultJwtBuilder"))).andReturn(instance)

        replay Classes, instance

        assertSame instance, Jwts.builder()

        verify Classes, instance
    }
}
