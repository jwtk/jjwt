package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.OctetPrivateJwk;
import io.jsonwebtoken.security.OctetPublicJwk;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

public class DefaultOctetPrivateJwk<T extends PrivateKey, P extends PublicKey> extends AbstractPrivateJwk<T, P, OctetPublicJwk<P>> implements OctetPrivateJwk<P, T> {

    static final Field<byte[]> D = Fields.bytes("d", "The private key").setSecret(true).build();

    static final Set<Field<?>> FIELDS = Collections.concat(DefaultOctetPublicJwk.FIELDS, D);

    DefaultOctetPrivateJwk(JwkContext<T> ctx, OctetPublicJwk<P> pubJwk) {
        super(ctx,
                // only public members are included in Private JWK Thumbprints per
                // https://www.rfc-editor.org/rfc/rfc7638#section-3.2.1
                DefaultOctetPublicJwk.THUMBPRINT_FIELDS, pubJwk);
    }
}
