package io.jsonwebtoken.impl

import io.jsonwebtoken.Header
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.lang.Function
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class IdLocatorTest {

    @Test
    void missingRequiredHeaderValueTest() {
        def msg = 'foo is required'
        def loc = new IdLocator('foo', msg, DummyIdFn.INSTANCE, DummyHeaderFn.INSTANCE)
        def header = new DefaultUnprotectedHeader()
        try {
            loc.apply(header)
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJwtHeaderInstanceTest() {
        def loc = new IdLocator('foo', 'foo', DummyIdFn.INSTANCE, DummyHeaderFn.INSTANCE)
        def header = new DefaultUnprotectedHeader([foo: 'foo'])
        try {
            loc.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = 'Unrecognized JWT \'foo\' header value: foo'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJwsHeaderInstanceTest() {
        def loc = new IdLocator('foo', 'foo', DummyIdFn.INSTANCE, DummyHeaderFn.INSTANCE)
        def header = new DefaultJwsHeader([foo: 'foo'])
        try {
            loc.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = 'Unrecognized JWS \'foo\' header value: foo'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void unlocatableJweHeaderInstanceTest() {
        def loc = new IdLocator('foo', 'foo', DummyIdFn.INSTANCE, DummyHeaderFn.INSTANCE)
        def header = new DefaultJweHeader([foo: 'foo'])
        try {
            loc.apply(header)
        } catch (UnsupportedJwtException expected) {
            String msg = 'Unrecognized JWE \'foo\' header value: foo'
            assertEquals msg, expected.getMessage()
        }
    }

    private static class DummyIdFn implements Function<String, String> {
        static final DummyIdFn INSTANCE = new DummyIdFn()

        @Override
        String apply(String s) {
            return null
        }
    }

    private static class DummyHeaderFn implements Function<Header, String> {
        static final DummyHeaderFn INSTANCE = new DummyHeaderFn()

        @Override
        String apply(Header header) {
            return null
        }
    }
}
