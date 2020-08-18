package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.SecretJwk;

import javax.crypto.SecretKey;
import java.util.Set;

class DefaultSecretJwk extends AbstractJwk<SecretKey> implements SecretJwk {

    static final String TYPE_VALUE = "oct";
    static final String K = "k";
    static final Set<String> PRIVATE_NAMES = Collections.setOf(K);

    DefaultSecretJwk(JwkContext<SecretKey> ctx) {
        super(ctx);
    }
}
