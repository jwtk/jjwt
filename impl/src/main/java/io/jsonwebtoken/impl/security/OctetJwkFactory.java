package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.util.Set;

public abstract class OctetJwkFactory<K extends Key, J extends Jwk<K>> extends AbstractFamilyJwkFactory<K, J> {

    OctetJwkFactory(Class<K> keyType, Set<Field<?>> fields) {
        super(DefaultOctetPublicJwk.TYPE_VALUE, keyType, fields);
    }

    @Override
    public boolean supports(Key key) {
        return super.supports(key) && EdwardsCurve.isEdwards(key);
    }

    protected EdwardsCurve getCurve(final FieldReadable reader) throws UnsupportedKeyException {
        Field<String> field = DefaultOctetPublicJwk.CRV;
        String crvId = reader.get(field);
        EdwardsCurve curve = EdwardsCurve.findById(crvId);
        if (curve == null) {
            String msg = "Unrecognized OKP JWK " + field + " value '" + crvId + "'";
            throw new UnsupportedKeyException(msg);
        }
        return curve;
    }
}
