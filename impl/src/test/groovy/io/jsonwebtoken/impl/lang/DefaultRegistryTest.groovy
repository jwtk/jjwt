package io.jsonwebtoken.impl.lang

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class DefaultRegistryTest {

    DefaultRegistry<String, String> reg

    @Before
    void setUp() {
        reg = new DefaultRegistry<>('test', 'id', ['a', 'b', 'c', 'd'], Functions.identity())
    }

    static void immutable(Closure c) {
        try {
            c.call()
            fail()
        } catch (UnsupportedOperationException expected) {
            String msg = 'Registries are immutable and cannot be modified.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testImmutable() {
        immutable { reg.put('foo', 'bar') }
        immutable { reg.putAll([foo: 'bar']) }
        immutable { reg.remove('kty') }
        immutable { reg.clear() }
    }
}
