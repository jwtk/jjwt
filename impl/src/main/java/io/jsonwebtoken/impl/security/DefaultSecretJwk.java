package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.SecretJwk;

import javax.crypto.SecretKey;
import java.util.Set;

class DefaultSecretJwk extends AbstractJwk<SecretKey> implements SecretJwk {

    static final String TYPE_VALUE = "oct";
    static final Field<byte[]> K = Fields.bytes("k", "Key Value").setSecret(true).build();
    static final Set<Field<?>> FIELDS = Collections.concat(AbstractJwk.FIELDS, K);

    DefaultSecretJwk(JwkContext<SecretKey> ctx) {
        super(ctx);
    }
}