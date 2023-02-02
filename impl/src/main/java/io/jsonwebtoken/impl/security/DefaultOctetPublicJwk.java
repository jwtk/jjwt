package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.PublicJwk;

import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public class DefaultOctetPublicJwk<T extends PublicKey> extends AbstractPublicJwk<T> implements PublicJwk<T> {

    static final String TYPE_VALUE = "OKP";
    static final Field<String> CRV = DefaultEcPublicJwk.CRV;
    static final Field<byte[]> X = Fields.bytes("x", "The public key").build();
    static final Set<Field<?>> FIELDS = Collections.concat(AbstractAsymmetricJwk.FIELDS, CRV, X);

    // https://www.rfc-editor.org/rfc/rfc8037#section-2 (last paragraph):
    static final List<Field<?>> THUMBPRINT_FIELDS = Collections.<Field<?>>of(CRV, KTY, X);

    DefaultOctetPublicJwk(JwkContext<T> ctx) {
        super(ctx, THUMBPRINT_FIELDS);
    }
}
