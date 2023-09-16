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

import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.ParameterReadable;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.impl.lang.RedactedSupplier;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.util.AbstractSet;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class ParameterMap implements Map<String, Object>, ParameterReadable, Nameable {

    protected final Registry<String, ? extends Parameter<?>> PARAMS;
    protected final Map<String, Object> values; // canonical values formatted per RFC requirements
    protected final Map<String, Object> idiomaticValues; // the values map with any RFC values converted to Java type-safe values where possible

    private final boolean initialized;

    private final boolean mutable;

    public ParameterMap(Set<Parameter<?>> params) {
        this(Parameters.registry(params));
    }

    public ParameterMap(Registry<String, ? extends Parameter<?>> registry) { // mutable constructor
        this(registry, null, true);
    }

    /**
     * Copy constructor producing an immutable instance.
     *
     * @param registry registry of idiomatic parameters relevant for the map values
     * @param values   map values
     */
    public ParameterMap(Registry<String, ? extends Parameter<?>> registry, Map<String, ?> values) {
        this(registry, Assert.notNull(values, "Map argument cannot be null."), false);
    }

    public ParameterMap(Registry<String, ? extends Parameter<?>> registry, Map<String, ?> values, boolean mutable) {
        Assert.notNull(registry, "Parameter registry cannot be null.");
        Assert.notEmpty(registry.values(), "Parameter registry cannot be empty.");
        this.PARAMS = registry;
        this.values = new LinkedHashMap<>();
        this.idiomaticValues = new LinkedHashMap<>();
        if (!Collections.isEmpty(values)) {
            putAll(values);
        }
        this.mutable = mutable;
        this.initialized = true;
    }

    private void assertMutable() {
        if (initialized && !mutable) {
            String msg = getName() + " instance is immutable and may not be modified.";
            throw new UnsupportedOperationException(msg);
        }
    }

    protected ParameterMap replace(Parameter<?> param) {
        Registry<String, ? extends Parameter<?>> registry = Parameters.replace(this.PARAMS, param);
        return new ParameterMap(registry, this, this.mutable);
    }

    @Override
    public String getName() {
        return "Map";
    }

    @Override
    public <T> T get(Parameter<T> param) {
        Assert.notNull(param, "Parameter cannot be null.");
        final String id = Assert.hasText(param.getId(), "Parameter id cannot be null or empty.");
        Object value = idiomaticValues.get(id);
        return param.cast(value);
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

    private static Object clean(Object o) {
        if (o instanceof String) {
            o = Strings.clean((String) o);
        }
        return o;
    }

    /**
     * Convenience method to put a value for an idiomatic param.
     *
     * @param param the param representing the property name to set
     * @param value the value to set
     * @return the previous value for the param, or {@code null} if there was no previous value
     * @since JJWT_RELEASE_VERSION
     */
    protected final <T> Object put(Parameter<T> param, Object value) {
        assertMutable();
        Assert.notNull(param, "Parameter cannot be null.");
        Assert.hasText(param.getId(), "Parameter id cannot be null or empty.");
        return apply(param, clean(value));
    }

    @Override
    public final Object put(String name, Object value) {
        assertMutable();
        name = Assert.notNull(Strings.clean(name), "Member name cannot be null or empty.");
        Parameter<?> param = PARAMS.get(name);
        if (param != null) {
            // standard property, represent it idiomatically:
            return put(param, value);
        } else {
            // non-standard or custom property, just apply directly:
            return nullSafePut(name, clean(value));
        }
    }

    private Object nullSafePut(String name, Object value) {
        if (Objects.isEmpty(value)) {
            return remove(name);
        } else {
            this.idiomaticValues.put(name, value);
            return this.values.put(name, value);
        }
    }

    private <T> Object apply(Parameter<T> param, Object rawValue) {

        final String id = param.getId();

        if (Objects.isEmpty(rawValue)) {
            return remove(id);
        }

        T idiomaticValue; // preferred Java format
        Object canonicalValue; // as required by the RFC
        try {
            idiomaticValue = param.applyFrom(rawValue);
            Assert.notNull(idiomaticValue, "Parameter's resulting idiomaticValue cannot be null.");
            canonicalValue = param.applyTo(idiomaticValue);
            Assert.notNull(canonicalValue, "Parameter's resulting canonicalValue cannot be null.");
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder(100);
            sb.append("Invalid ").append(getName()).append(" ").append(param).append(" value");
            if (param.isSecret()) {
                sb.append(": ").append(RedactedSupplier.REDACTED_VALUE);
            } else if (!(rawValue instanceof byte[])) {
                // don't print raw byte array gibberish.  We can't base64[url] encode it either because that could
                // make the exception message confusing: the developer would see an encoded string and could think
                // that was the rawValue specified when it wasn't.
                sb.append(": ").append(Objects.nullSafeToString(rawValue));
            }
            sb.append(". ").append(e.getMessage());
            String msg = sb.toString();
            throw new IllegalArgumentException(msg, e);
        }
        Object retval = nullSafePut(id, canonicalValue);
        this.idiomaticValues.put(id, idiomaticValue);
        return retval;
    }

    @Override
    public Object remove(Object key) {
        assertMutable();
        this.idiomaticValues.remove(key);
        return this.values.remove(key);
    }

    @Override
    public void putAll(Map<? extends String, ?> m) {
        if (m == null) {
            return;
        }
        for (Map.Entry<? extends String, ?> entry : m.entrySet()) {
            String s = entry.getKey();
            put(s, entry.getValue());
        }
    }

    @Override
    public void clear() {
        assertMutable();
        this.values.clear();
        this.idiomaticValues.clear();
    }

    @Override
    public Set<String> keySet() {
        return new KeySet();
    }

    @Override
    public Collection<Object> values() {
        return new ValueSet();
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        return new EntrySet();
    }

    @Override
    public String toString() {
        return values.toString();
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

    private abstract class ParameterMapSet<T> extends AbstractSet<T> {

        @Override
        public int size() {
            return ParameterMap.this.size();
        }
    }

    private class KeySet extends ParameterMapSet<String> {
        @Override
        public Iterator<String> iterator() {
            return new KeyIterator();
        }
    }

    private class ValueSet extends ParameterMapSet<Object> {
        @Override
        public Iterator<Object> iterator() {
            return new ValueIterator();
        }
    }

    private class EntrySet extends ParameterMapSet<Entry<String, Object>> {
        @Override
        public Iterator<Entry<String, Object>> iterator() {
            return new EntryIterator();
        }
    }

    private abstract class ParameterMapIterator<T> implements Iterator<T> {

        final Iterator<Map.Entry<String, Object>> i;

        transient Map.Entry<String, Object> current;

        ParameterMapIterator() {
            this.i = ParameterMap.this.values.entrySet().iterator();
            this.current = null;
        }

        @Override
        public boolean hasNext() {
            return i.hasNext();
        }

        protected Map.Entry<String, Object> nextEntry() {
            current = i.next();
            return current;
        }

        @Override
        public void remove() {
            if (current == null) {
                throw new IllegalStateException();
            }
            String key = current.getKey();
            ParameterMap.this.remove(key);
        }
    }

    private class ValueIterator extends ParameterMapIterator<Object> {
        @Override
        public Object next() {
            return nextEntry().getValue();
        }
    }

    private class KeyIterator extends ParameterMapIterator<String> {
        @Override
        public String next() {
            return nextEntry().getKey();
        }
    }

    private class EntryIterator extends ParameterMapIterator<Entry<String, Object>> {
        @Override
        public Entry<String, Object> next() {
            return nextEntry();
        }
    }

}
