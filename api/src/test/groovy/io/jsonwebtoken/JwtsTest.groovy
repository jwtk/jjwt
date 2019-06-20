package io.jsonwebtoken

import io.jsonwebtoken.factory.JwtFactory
import io.jsonwebtoken.factory.FactoryLoader
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
@PrepareForTest([FactoryLoader])
class JwtsTest {

    static JwtFactory factory = mock(JwtFactory)

    @BeforeClass
    static void prepareFactory() {
        mockStatic(FactoryLoader)

        expect(FactoryLoader.loadFactory()).andReturn(factory).anyTimes()

        replay FactoryLoader
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
