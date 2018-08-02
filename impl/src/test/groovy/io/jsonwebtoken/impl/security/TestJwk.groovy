package io.jsonwebtoken.impl.security

class TestJwk<T extends TestJwk> extends AbstractJwk<T> {
    def TestJwk() {
        super("test")
    }
}
