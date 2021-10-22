package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Jwk;

import java.security.Key;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

public abstract class AbstractJwk<K extends Key> implements Jwk<K> {

    static final Field<String> ALG = Fields.string("alg", "Algorithm");
    public static final Field<String> KID = Fields.string("kid", "Key ID");
    static final Field<Set<String>> KEY_OPS = Fields.stringSet("key_ops", "Key Operations");
    static final Field<String> KTY = Fields.string("kty", "Key Type");
    static final Set<Field<?>> FIELDS = Collections.setOf(ALG, KID, KEY_OPS, KTY);

    public static final String IMMUTABLE_MSG = "JWKs are immutable may not be modified.";
    protected final JwkContext<K> context;

    AbstractJwk(JwkContext<K> ctx) {
        this.context = Assert.notNull(ctx, "JwkContext cannot be null.");
        Assert.isTrue(!ctx.isEmpty(), "JwkContext cannot be empty.");
        Assert.hasText(ctx.getType(), "JwkContext type cannot be null or empty.");
        Assert.notNull(ctx.getKey(), "JwkContext key cannot be null.");
    }

    @Override
    public String getType() {
        return this.context.getType();
    }

    @Override
    public Set<String> getOperations() {
        return this.context.getOperations();
    }

    @Override
    public String getAlgorithm() {
        return this.context.getAlgorithm();
    }

    @Override
    public String getId() {
        return this.context.getId();
    }

    @Override
    public K toKey() {
        return this.context.getKey();
    }

    @Override
    public int size() {
        return this.context.size();
    }

    @Override
    public boolean isEmpty() {
        return this.context.isEmpty();
    }

    @Override
    public boolean containsKey(Object key) {
        return this.context.containsKey(key);
    }

    @Override
    public boolean containsValue(Object value) {
        return this.context.containsValue(value);
    }

    @Override
    public Object get(Object key) {
        return this.context.get(key);
    }

    @Override
    public Set<String> keySet() {
        return this.context.keySet();
    }

    @Override
    public Collection<Object> values() {
        return this.context.values();
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        return this.context.entrySet();
    }

    private static Object immutable() {
        throw new UnsupportedOperationException(IMMUTABLE_MSG);
    }

    @Override
    public Object put(String s, Object o) {
        return immutable();
    }

    @Override
    public Object remove(Object o) {
        return immutable();
    }

    @Override
    public void putAll(Map<? extends String, ?> m) {
        immutable();
    }

    @Override
    public void clear() {
        immutable();
    }

    @Override
    public String toString() {
        return this.context.toString();
    }

    @Override
    public int hashCode() {
        return this.context.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Map) {
            return this.context.equals(obj);
        }
        return false;
    }
}
