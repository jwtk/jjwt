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
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class JwtMap implements Map<String, Object> {

    private static final String GROOVY_PRESENCE_CLASS_NAME = "org.codehaus.groovy.runtime.InvokerHelper";
    private static final String GROOVY_PRESENCE_CLASS_METHOD_NAME = "formatMap";
    private static final boolean GROOVY_PRESENT = Classes.isAvailable(GROOVY_PRESENCE_CLASS_NAME);

    static final String REDACTED_VALUE = "<redacted>";
    protected final Map<String, Object> values; // canonical values formatted per RFC requirements
    protected final Map<String, Object> idiomaticValues; // the values map with any RFC values converted to Java type-safe values where possible
    protected final Map<String, Object> redactedValues; // the values map with any sensitive/secret values redacted. Used in the toString implementation.
    protected final Map<String, Field<?>> FIELDS;
    private final boolean hasSecretFields;

    public JwtMap(Set<Field<?>> fieldSet) {
        Assert.notEmpty(fieldSet, "Fields cannot be null or empty.");
        Map<String, Field<?>> fields = new LinkedHashMap<>();
        boolean hasSecretFields = false;
        for (Field<?> field : fieldSet) {
            fields.put(field.getId(), field);
            if (field.isSecret()) {
                hasSecretFields = true;
            }
        }
        this.hasSecretFields = hasSecretFields;
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

    /**
     * Convenience method to put a value for a canonical field.
     *
     * @param field the field representing the property name to set
     * @param value the value to set
     * @return the previous value for the field name, or {@code null} if there was no previous value
     * @since JJWT_RELEASE_VERSION
     */
    protected Object put(Field<?> field, Object value) {
        return put(field.getId(), value);
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
            String msg = "Invalid " + getName() + " " + field + " value: " + sval + ". Cause: " + e.getMessage();
            throw new IllegalArgumentException(msg, e);
        }
        Object retval = nullSafePut(id, canonicalValue);
        this.idiomaticValues.put(id, idiomaticValue);
        return retval;
    }

    protected String getName() {
        return "Map";
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
        for (Map.Entry<? extends String, ?> entry : m.entrySet()) {
            String s = entry.getKey();
            put(s, entry.getValue());
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

    // MAINTAINER'S NOTE:
    //
    // BE VERY CAREFUL about moving this method - it's exact location in this
    // file ties it to its implementation per StackTrace depth expectations.
    //
    // This behavior (and it's stack depth) is asserted in the
    // DefaultJwkContextTest.testGStringPrintsRedactedValues() test case.  If you
    // change the location of this method, you must update that test as well.
    protected boolean preferRedactedEntrySet() {
        // For better performance, only execute the groovy stack count if this instance has secret fields
        // (otherwise, we don't need to worry about redaction) and Groovy is detected:
        if (this.hasSecretFields && GROOVY_PRESENT) {
            Throwable t = new Throwable();
            StackTraceElement[] elements = t.getStackTrace();
            Assert.gt(Arrays.length(elements), 2, "StackTraceElement array must be greater than 2.");
            return GROOVY_PRESENCE_CLASS_NAME.equals(elements[2].getClassName()) &&
                    GROOVY_PRESENCE_CLASS_METHOD_NAME.equals(elements[2].getMethodName());
        }
        return false;
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        if (preferRedactedEntrySet()) {
            return this.redactedValues.entrySet();
        }
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
