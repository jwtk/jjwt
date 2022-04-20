/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.security.JwkContext;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class JwtMap implements Map<String, Object> {

    static final String REDACTED_VALUE = "<redacted>";
    protected final Map<String, Object> values; // canonical values formatted per RFC requirements
    protected final Map<String, Object> idiomaticValues; // the values map with any RFC values converted to Java type-safe values where possible
    protected final Map<String, Object> redactedValues; // the values map with any sensitive/secret values redacted. Used in the toString implementation.
    protected final Map<String, Field<?>> FIELDS;

    public JwtMap(Set<Field<?>> fieldSet) {
        Assert.notEmpty(fieldSet, "Fields cannot be null or empty.");
        Map<String, Field<?>> fields = new LinkedHashMap<>();
        for (Field<?> field : fieldSet) {
            fields.put(field.getId(), field);
        }
        this.FIELDS = java.util.Collections.unmodifiableMap(fields);
        this.values = new LinkedHashMap<>();
        this.idiomaticValues = new LinkedHashMap<>();
        this.redactedValues = new LinkedHashMap<>();
    }

    public JwtMap(Set<Field<?>> fieldSet, Map<String, ?> values) {
        this(fieldSet);
        Assert.notNull(values, "Map argument cannot be null.");
        putAll(values);
    }

    protected boolean isSecret(String id) {
        Field<?> field = FIELDS.get(id);
        return field != null && field.isSecret();
    }

    public static boolean isReduceableToNull(Object v) {
        return v == null ||
            (v instanceof String && !Strings.hasText((String) v)) ||
            (v instanceof Collection && Collections.isEmpty((Collection<?>) v)) ||
            (v instanceof Map && Collections.isEmpty((Map<?, ?>) v)) ||
            (v.getClass().isArray() && Array.getLength(v) == 0);
    }

    protected Object idiomaticGet(String key) {
        return this.idiomaticValues.get(key);
    }

    @SuppressWarnings("unchecked")
    protected <T> T idiomaticGet(Field<T> field) {
        return (T) this.idiomaticValues.get(field.getId());
    }

    @Override
    public int size() {
        return values.size();
    }

    @Override
    public boolean isEmpty() {
        return values.isEmpty();
    }

    @Override
    public boolean containsKey(Object o) {
        return values.containsKey(o);
    }

    @Override
    public boolean containsValue(Object o) {
        return values.containsValue(o);
    }

    @Override
    public Object get(Object o) {
        return values.get(o);
    }

    @Override
    public Object put(String name, Object value) {
        name = Assert.notNull(Strings.clean(name), "Member name cannot be null or empty.");
        if (value instanceof String) {
            value = Strings.clean((String) value);
        }
        return idiomaticPut(name, value);
    }

    // ensures that if a property name matches an RFC-specified name, that value can be represented
    // as an idiomatic type-safe Java value in addition to the canonical RFC/encoded value.
    private Object idiomaticPut(String name, Object value) {
        Assert.stateNotNull(name, "Name cannot be null."); // asserted by caller
        Field<?> field = FIELDS.get(name);
        if (field != null) { //Setting a JWA-standard property - let's ensure we can represent it idiomatically:
            return apply(field, value);
        } else { //non-standard/custom property:
            return nullSafePut(name, value);
        }
    }

    protected Object nullSafePut(String name, Object value) {
        if (isReduceableToNull(value)) {
            return remove(name);
        } else {
            Object redactedValue = isSecret(name) ? REDACTED_VALUE : value;
            this.redactedValues.put(name, redactedValue);
            this.idiomaticValues.put(name, value);
            return this.values.put(name, value);
        }
    }

    protected <T> Object apply(Field<T> field, Object rawValue) {

        final String id = field.getId();

        if (isReduceableToNull(rawValue)) {
            return remove(id);
        }

        T idiomaticValue; // preferred Java format
        Object canonicalValue; // as required by the RFC
        try {
            idiomaticValue = field.applyFrom(rawValue);
            Assert.notNull(idiomaticValue, "Converter's resulting idiomaticValue cannot be null.");
            canonicalValue = field.applyTo(idiomaticValue);
            Assert.notNull(canonicalValue, "Converter's resulting canonicalValue cannot be null.");
        } catch (IllegalArgumentException e) {
            Object sval = field.isSecret() ? REDACTED_VALUE : rawValue;
            String msg = "Invalid " + getName() + " " + field + " value [" + sval + "]. Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
        Object retval = nullSafePut(id, canonicalValue);
        this.idiomaticValues.put(id, idiomaticValue);
        return retval;
    }

    private String getName() {
        if (this instanceof JweHeader) {
            return "JWE header";
        } else if (this instanceof JwsHeader) {
            return "JWS header";
        } else if (this instanceof Header) {
            return "JWT header";
        } else if (this instanceof Jwk || this instanceof JwkContext) {
            Object value = values.get("kty");
            if ("oct".equals(value)) {
                value = "Secret";
            }
            return value != null ? value + " JWK" : "JWK";
        } else {
            return "Map";
        }
    }

    @Override
    public Object remove(Object key) {
        this.redactedValues.remove(key);
        this.idiomaticValues.remove(key);
        return this.values.remove(key);
    }

    @Override
    public void putAll(Map<? extends String, ?> m) {
        if (m == null) {
            return;
        }
        for (String s : m.keySet()) {
            put(s, m.get(s));
        }
    }

    @Override
    public void clear() {
        this.values.clear();
        this.idiomaticValues.clear();
        this.redactedValues.clear();
    }

    @Override
    public Set<String> keySet() {
        return values.keySet();
    }

    @Override
    public Collection<Object> values() {
        return values.values();
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        return values.entrySet();
    }

    @Override
    public String toString() {
        return redactedValues.toString();
    }

    @Override
    public int hashCode() {
        return values.hashCode();
    }

    @SuppressWarnings("EqualsWhichDoesntCheckParameterClass")
    @Override
    public boolean equals(Object obj) {
        return values.equals(obj);
    }
}
