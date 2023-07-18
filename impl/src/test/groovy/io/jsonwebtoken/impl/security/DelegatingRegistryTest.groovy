package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.DefaultRegistry
import io.jsonwebtoken.impl.lang.Functions
import io.jsonwebtoken.lang.Registry
import org.junit.Test

import static org.junit.Assert.assertEquals

class DelegatingRegistryTest {

    @Test
    void testSize() {
        def values = ['foo', 'bar', 'baz']
        Registry<String, String> reg = new TestDelegatingRegistry(values)
        assertEquals values.size(), reg.size()
    }

    final class TestDelegatingRegistry extends DelegatingRegistry<String> {
        TestDelegatingRegistry(Collection<String> values) {
            super(new DefaultRegistry<String, String>('test', 'id', values, Functions.identity()))
        }
    }
}
