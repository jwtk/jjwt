package io.jsonwebtoken.impl.security

import java.security.Provider

class TestProvider extends Provider {

    TestProvider() {
        this('test')
    }

    TestProvider(String name) {
        super(name, 1.0d, 'info')
    }
}
