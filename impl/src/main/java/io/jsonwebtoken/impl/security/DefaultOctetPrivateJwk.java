package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.PrivateJwk;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

public class DefaultOctetPrivateJwk<T extends PrivateKey, P extends PublicKey, K extends PublicJwk<P>>
        extends AbstractPrivateJwk<T, P, K> implements PrivateJwk<T, P, K> {

    static final Field<byte[]> D = Fields.bytes("d", "The private key").setSecret(true).build();

    static final Set<Field<?>> FIELDS = Collections.concat(DefaultOctetPublicJwk.FIELDS, D);

    DefaultOctetPrivateJwk(JwkContext<T> ctx, K pubJwk) {
        super(ctx,
                // only public members are included in Private JWKs per
                // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
                DefaultOctetPublicJwk.THUMBPRINT_FIELDS,
                pubJwk);
    }
}
