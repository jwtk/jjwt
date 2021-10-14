package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.Header
import io.jsonwebtoken.Locator
import io.jsonwebtoken.impl.DefaultJweHeader
import org.junit.Test

import static org.junit.Assert.assertEquals

class LocatorFunctionTest {

    @Test
    void testApply() {
        final int value = 42
        def locator = new StaticLocator(value)
        def fn = new LocatorFunction(locator)
        assertEquals value, fn.apply(new DefaultJweHeader())
    }

    static class StaticLocator<H extends Header<H>, R> implements Locator<H, R> {
        private final R o;
        StaticLocator(R o) {
            this.o = o;
        }
        @Override
        R locate(H header) {
            return o;
        }
    }
}
