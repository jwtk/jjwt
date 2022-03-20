package io.jsonwebtoken

import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import org.junit.Test

import static org.junit.Assert.assertNull
import static org.junit.Assert.assertSame

class LocatorAdapterTest {

    @Test
    void testJwtHeader() {
        Header input = new DefaultHeader()
        def locator = new LocatorAdapter() {
            @Override
            protected Object doLocate(Header header) {
                return header
            }
        }
        assertSame input, locator.locate(input as Header)
    }

    @Test
    void testJwtHeaderWithoutOverride() {
        Header input = new DefaultHeader()
        Locator locator = new LocatorAdapter()
        assertNull locator.locate(input as Header)
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
        Locator locator = new LocatorAdapter()
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
        def locator = new LocatorAdapter()
        assertNull locator.locate(input as Header)
    }
}
