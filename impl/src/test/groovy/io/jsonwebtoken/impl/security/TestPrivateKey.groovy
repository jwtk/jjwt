package io.jsonwebtoken.impl.security

import javax.security.auth.DestroyFailedException
import java.security.PrivateKey

class TestPrivateKey extends TestKey implements PrivateKey {

    boolean destroyed

    @Override
    void destroy() throws DestroyFailedException {
        destroyed = true
    }

    @Override
    boolean isDestroyed() {
        return destroyed
    }
}
