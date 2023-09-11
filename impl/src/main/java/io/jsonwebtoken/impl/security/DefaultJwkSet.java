package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.FieldMap;
import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

public class DefaultJwkSet extends FieldMap implements JwkSet {

    @SuppressWarnings({"unchecked", "RedundantCast"})
    static <T extends Jwk<?>> Field<Set<T>> field(Converter<T, ?> converter) {
        return Fields.builder((Class<T>)(Class<?>)Jwk.class)
                .setConverter(converter).set()
                .setId("keys").setName("JSON Web Keys")
                .build();
    }

    static final Field<Set<Jwk<?>>> KEYS = field(JwkConverter.ANY);

    public DefaultJwkSet(Field<Set<Jwk<?>>> field, Map<String, ?> src) {
        super(Fields.registry(field), src);
    }

    @Override
    public Collection<? extends Jwk<?>> getKeys() {
        return get(KEYS);
    }
}
