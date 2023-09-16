/*
 * Copyright (C) 2021 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.lang.Supplier;
import io.jsonwebtoken.security.HashAlgorithm;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkThumbprint;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyOperation;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class AbstractJwk<K extends Key> implements Jwk<K>, ParameterReadable, Nameable {

    static final Parameter<String> ALG = Parameters.string("alg", "Algorithm");
    public static final Parameter<String> KID = Parameters.string("kid", "Key ID");
    static final Parameter<Set<KeyOperation>> KEY_OPS =
            Parameters.builder(KeyOperation.class).setConverter(KeyOperationConverter.DEFAULT)
                    .set().setId("key_ops").setName("Key Operations").build();
    static final Parameter<String> KTY = Parameters.string("kty", "Key Type");
    static final Set<Parameter<?>> PARAMS = Collections.setOf(ALG, KID, KEY_OPS, KTY);
    public static final String IMMUTABLE_MSG = "JWKs are immutable and may not be modified.";

    protected final JwkContext<K> context;
    private final List<Parameter<?>> THUMBPRINT_PARAMS;
    private final int hashCode;

    /**
     * @param ctx              the backing JwkContext containing the JWK parameter values.
     * @param thumbprintParams the required parameters to include in the JWK Thumbprint canonical JSON representation,
     *                         sorted in lexicographic order as defined by
     *                         <a href="https://www.rfc-editor.org/rfc/rfc7638#section-3.2">RFC 7638, Section 3.2</a>.
     */
    AbstractJwk(JwkContext<K> ctx, List<Parameter<?>> thumbprintParams) {
        this.context = Assert.notNull(ctx, "JwkContext cannot be null.");
        Assert.isTrue(!ctx.isEmpty(), "JwkContext cannot be empty.");
        Assert.hasText(ctx.getType(), "JwkContext type cannot be null or empty.");
        Assert.notNull(ctx.getKey(), "JwkContext key cannot be null.");
        this.THUMBPRINT_PARAMS = Assert.notEmpty(thumbprintParams, "JWK Thumbprint parameters cannot be null or empty.");
        HashAlgorithm idThumbprintAlg = ctx.getIdThumbprintAlgorithm();
        if (!Strings.hasText(getId()) && idThumbprintAlg != null) {
            JwkThumbprint thumbprint = thumbprint(idThumbprintAlg);
            String kid = thumbprint.toString();
            ctx.setId(kid);
        }
        this.hashCode = computeHashCode();
    }

    /**
     * Compute and return the JWK hashCode.  As JWKs are immutable, this value will be cached as a final constant
     * upon JWK instantiation. This uses the JWK's thumbprint parameters during computation, but differs from
     * JwkThumbprint calculation in two ways:
     * <ol>
     *     <li>JwkThumbprints use a MessageDigest calculation, which is unnecessary overhead for a hashcode</li>
     *     <li>The hashCode calculation uses each parameter's idiomatic (Java) object value instead of the
     *     JwkThumbprint-required canonical (String) value.</li>
     * </ol>
     *
     * @return the JWK hashcode
     */
    private int computeHashCode() {
        List<Object> list = new ArrayList<>(this.THUMBPRINT_PARAMS.size() + 1 /* possible discriminator */);
        // So we don't leak information about the private key value, we need a discriminator to ensure that
        // public and private key hashCodes are not identical (in case both JWKs need to be in the same hash set).
        // So we add a discriminator String to the list of values that are used during hashCode calculation
        Key key = Assert.notNull(toKey(), "JWK toKey() value cannot be null.");
        if (key instanceof PublicKey) {
            list.add("Public");
        } else if (key instanceof PrivateKey) {
            list.add("Private");
        }
        for (Parameter<?> param : this.THUMBPRINT_PARAMS) {
            // Unlike thumbprint calculation, we get the idiomatic (Java) value, not canonical (String) value
            // (We could have used either actually, but the idiomatic value hashCode calculation is probably
            // faster).
            Object val = Assert.notNull(get(param), "computeHashCode: Parameter idiomatic value cannot be null.");
            list.add(val);
        }
        return Objects.nullSafeHashCode(list.toArray());
    }

    private String getRequiredThumbprintValue(Parameter<?> param) {
        Object value = get(param.getId());
        if (value instanceof Supplier) {
            value = ((Supplier<?>) value).get();
        }
        return Assert.isInstanceOf(String.class, value, "Parameter canonical value is not a String.");
    }

    /**
     * Returns the JWK's canonically ordered JSON for JWK thumbprint computation as defined by
     * <a href="https://www.rfc-editor.org/rfc/rfc7638#section-3.2">RFC 7638, Section 3.2</a>.
     *
     * @return the JWK's canonically ordered JSON for JWK thumbprint computation.
     */
    private String toThumbprintJson() {
        StringBuilder sb = new StringBuilder().append('{');
        Iterator<Parameter<?>> i = this.THUMBPRINT_PARAMS.iterator();
        while (i.hasNext()) {
            Parameter<?> param = i.next();
            String value = getRequiredThumbprintValue(param);
            sb.append('"').append(param.getId()).append("\":\"").append(value).append('"');
            if (i.hasNext()) {
                sb.append(",");
            }
        }
        sb.append('}');
        return sb.toString();
    }

    @Override
    public JwkThumbprint thumbprint() {
        return thumbprint(Jwks.HASH.SHA256);
    }

    @Override
    public JwkThumbprint thumbprint(final HashAlgorithm alg) {
        String json = toThumbprintJson();
        Assert.hasText(json, "Canonical JWK Thumbprint JSON cannot be null or empty.");
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8); // https://www.rfc-editor.org/rfc/rfc7638#section-3 #2
        byte[] digest = alg.digest(new DefaultRequest<>(bytes, this.context.getProvider(), this.context.getRandom()));
        return new DefaultJwkThumbprint(digest, alg);
    }

    @Override
    public String getType() {
        return this.context.getType();
    }

    @Override
    public String getName() {
        return this.context.getName();
    }

    @Override
    public Set<KeyOperation> getOperations() {
        return Collections.immutable(this.context.getOperations());
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
        Object val = this.context.get(key);
        if (val instanceof Map) {
            return Collections.immutable((Map<?, ?>) val);
        } else if (val instanceof Collection) {
            return Collections.immutable((Collection<?>) val);
        } else if (Objects.isArray(val)) {
            return Arrays.copy(val);
        } else {
            return val;
        }
    }

    @Override
    public <T> T get(Parameter<T> param) {
        return this.context.get(param);
    }

    @Override
    public Set<String> keySet() {
        return Collections.immutable(this.context.keySet());
    }

    @Override
    public Collection<Object> values() {
        return Collections.immutable(this.context.values());
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        return Collections.immutable(this.context.entrySet());
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
    public final int hashCode() {
        return this.hashCode;
    }

    @Override
    public final boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj instanceof Jwk<?>) {
            Jwk<?> other = (Jwk<?>) obj;
            // this.getType() guaranteed non-null in constructor:
            return getType().equals(other.getType()) && equals(other);
        }
        return false;
    }

    protected abstract boolean equals(Jwk<?> jwk);
}
