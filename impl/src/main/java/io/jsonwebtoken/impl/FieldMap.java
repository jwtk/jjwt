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

import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.Fields;
import io.jsonwebtoken.impl.lang.Nameable;
import io.jsonwebtoken.impl.lang.RedactedSupplier;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.lang.reflect.Array;
import java.util.AbstractSet;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class FieldMap implements Map<String, Object>, FieldReadable, Nameable {

    protected final Registry<String, ? extends Field<?>> FIELDS;
    protected final Map<String, Object> values; // canonical values formatted per RFC requirements
    protected final Map<String, Object> idiomaticValues; // the values map with any RFC values converted to Java type-safe values where possible

    private final boolean initialized;

    private final boolean mutable;

    public FieldMap(Set<Field<?>> fields) {
        this(Fields.registry(fields));
    }

    public FieldMap(Registry<String, ? extends Field<?>> fields) { // mutable constructor
        this(fields, null, true);
    }

    /**
     * Copy constructor producing an immutable instance.
     *
     * @param fields registry fields
     * @param values field values
     */
    public FieldMap(Registry<String, ? extends Field<?>> fields, Map<String, ?> values) {
        this(fields, Assert.notNull(values, "Map argument cannot be null."), false);
    }

    protected FieldMap(Registry<String, ? extends Field<?>> fields, Map<String, ?> values, boolean mutable) {
        Assert.notNull(fields, "Field registry cannot be null.");
        Assert.notEmpty(fields.values(), "Field registry cannot be empty.");
        this.FIELDS = fields;
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

    protected FieldMap replace(Field<?> field) {
        Registry<String, ? extends Field<?>> registry = Fields.replace(this.FIELDS, field);
        return new FieldMap(registry, this, this.mutable);
    }

    @Override
    public String getName() {
        return "Map";
    }

    public static boolean isReducibleToNull(Object v) {
        return v == null ||
                (v instanceof String && !Strings.hasText((String) v)) ||
                (v instanceof Collection && Collections.isEmpty((Collection<?>) v)) ||
                (v instanceof Map && Collections.isEmpty((Map<?, ?>) v)) ||
                (v.getClass().isArray() && Array.getLength(v) == 0);
    }

    @Override
    public <T> T get(Field<T> field) {
        Assert.notNull(field, "Field cannot be null.");
        final String id = Assert.hasText(field.getId(), "Field id cannot be null or empty.");
        Object value = idiomaticValues.get(id);
        return field.cast(value);
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
     * Convenience method to put a value for an idiomatic field.
     *
     * @param field the field representing the property name to set
     * @param value the value to set
     * @return the previous value for the field, or {@code null} if there was no previous value
     * @since JJWT_RELEASE_VERSION
     */
    protected final <T> Object put(Field<T> field, Object value) {
        assertMutable();
        Assert.notNull(field, "Field cannot be null.");
        Assert.hasText(field.getId(), "Field id cannot be null or empty.");
        return apply(field, clean(value));
    }

    @Override
    public final Object put(String name, Object value) {
        assertMutable();
        name = Assert.notNull(Strings.clean(name), "Member name cannot be null or empty.");
        Field<?> field = FIELDS.get(name);
        if (field != null) {
            // standard property, represent it idiomatically:
            return put(field, value);
        } else {
            // non-standard or custom property, just apply directly:
            return nullSafePut(name, clean(value));
        }
    }

    private Object nullSafePut(String name, Object value) {
        if (isReducibleToNull(value)) {
            return remove(name);
        } else {
            this.idiomaticValues.put(name, value);
            return this.values.put(name, value);
        }
    }

    private <T> Object apply(Field<T> field, Object rawValue) {

        final String id = field.getId();

        if (isReducibleToNull(rawValue)) {
            return remove(id);
        }

        T idiomaticValue; // preferred Java format
        Object canonicalValue; // as required by the RFC
        try {
            idiomaticValue = field.applyFrom(rawValue);
            Assert.notNull(idiomaticValue, "Field's resulting idiomaticValue cannot be null.");
            canonicalValue = field.applyTo(idiomaticValue);
            Assert.notNull(canonicalValue, "Field's resulting canonicalValue cannot be null.");
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder(100);
            sb.append("Invalid ").append(getName()).append(" ").append(field).append(" value");
            if (field.isSecret()) {
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

    private abstract class FieldMapSet<T> extends AbstractSet<T> {

        @Override
        public int size() {
            return FieldMap.this.size();
        }
    }

    private class KeySet extends FieldMapSet<String> {
        @Override
        public Iterator<String> iterator() {
            return new KeyIterator();
        }
    }

    private class ValueSet extends FieldMapSet<Object> {
        @Override
        public Iterator<Object> iterator() {
            return new ValueIterator();
        }
    }

    private class EntrySet extends FieldMapSet<Map.Entry<String, Object>> {
        @Override
        public Iterator<Entry<String, Object>> iterator() {
            return new EntryIterator();
        }
    }

    private abstract class FieldMapIterator<T> implements Iterator<T> {

        final Iterator<Map.Entry<String, Object>> i;

        transient Map.Entry<String, Object> current;

        FieldMapIterator() {
            this.i = FieldMap.this.values.entrySet().iterator();
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
            FieldMap.this.remove(key);
        }
    }

    private class ValueIterator extends FieldMapIterator<Object> {
        @Override
        public Object next() {
            return nextEntry().getValue();
        }
    }

    private class KeyIterator extends FieldMapIterator<String> {
        @Override
        public String next() {
            return nextEntry().getKey();
        }
    }

    private class EntryIterator extends FieldMapIterator<Map.Entry<String, Object>> {
        @Override
        public Entry<String, Object> next() {
            return nextEntry();
        }
    }

}
