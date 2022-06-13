package io.jsonwebtoken

import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.DefaultUnprotectedHeader
import org.junit.Test

import static org.junit.Assert.assertNull
import static org.junit.Assert.assertSame

class LocatorAdapterTest {

    @Test
    void testJwtHeader() {
        Header input = new DefaultUnprotectedHeader()
        def locator = new LocatorAdapter() {
            @Override
            protected Object locate(UnprotectedHeader header) {
                return header
            }
        }
        assertSame input, locator.locate(input as Header /* force Groovy to avoid signature erasure */)
    }

    @Test
    void testJwtHeaderWithoutOverride() {
        Header input = new DefaultUnprotectedHeader()
        Locator locator = new LocatorAdapter() {}
        assertNull locator.locate(input as Header /* force Groovy to avoid signature erasure */)
    }

    @Test
    void testJwsHeader() {
        Header input = new DefaultJwsHeader()
        Locator locator = new LocatorAdapter() {
            @Override
            protected Object locate(JwsHeader header) {
                return header
            }
        }
        assertSame input, locator.locate(input as Header /* force Groovy to avoid signature erasure */)
    }

    @Test
    void testJwsHeaderWithoutOverride() {
        Header input = new DefaultJwsHeader()
        Locator locator = new LocatorAdapter() {}
        assertNull locator.locate(input as Header)
    }

    @Test
    void testJweHeader() {
        JweHeader input = new DefaultJweHeader()
        def locator = new LocatorAdapter() {
            @Override
            protected Object locate(JweHeader header) {
                return header
            }
        }
        assertSame input, locator.locate(input as Header)
    }

    @Test
    void testJweHeaderWithoutOverride() {
        JweHeader input = new DefaultJweHeader()
        def locator = new LocatorAdapter() {}
        assertNull locator.locate(input as Header)
    }
}
