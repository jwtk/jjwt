package io.jsonwebtoken.impl.security

class TestJwk<T extends TestJwk<T>> extends AbstractJwk<T> {
    def TestJwk() {
        super("test")
    }
}
