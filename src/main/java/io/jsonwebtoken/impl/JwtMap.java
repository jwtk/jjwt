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

import io.jsonwebtoken.lang.Assert;

import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class JwtMap implements Map<String,Object> {

    private final Map<String, Object> map;

    public JwtMap() {
        this(new LinkedHashMap<String, Object>());
    }

    public JwtMap(Map<String, Object> map) {
        Assert.notNull(map, "Map argument cannot be null.");
        this.map = map;
    }

    protected String getString(String name) {
        Object v = get(name);
        return v != null ? String.valueOf(v) : null;
    }

    protected static Date toDate(Object v, String name) {
        if (v == null) {
            return null;
        } else if (v instanceof Date) {
            return (Date) v;
        } else if (v instanceof Number) {
            // https://github.com/jwtk/jjwt/issues/122:
            // The JWT RFC *mandates* NumericDate values are represented as seconds.
            // Because Because java.util.Date requires milliseconds, we need to multiply by 1000:
            long seconds = ((Number) v).longValue();
            long millis = seconds * 1000;
            return new Date(millis);
        } else if (v instanceof String) {
            // https://github.com/jwtk/jjwt/issues/122
            // The JWT RFC *mandates* NumericDate values are represented as seconds.
            // Because Because java.util.Date requires milliseconds, we need to multiply by 1000:
            long seconds = Long.parseLong((String) v);
            long millis = seconds * 1000;
            return new Date(millis);
        } else {
            throw new IllegalStateException("Cannot convert '" + name + "' value [" + v + "] to Date instance.");
        }
    }

    protected void setValue(String name, Object v) {
        if (v == null) {
            map.remove(name);
        } else {
            map.put(name, v);
        }
    }

    protected Date getDate(String name) {
        Object v = map.get(name);
        return toDate(v, name);
    }

    protected void setDate(String name, Date d) {
        if (d == null) {
            map.remove(name);
        } else {
            long seconds = d.getTime() / 1000;
            map.put(name, seconds);
        }
    }

    @Override
    public int size() {
        return map.size();
    }

    @Override
    public boolean isEmpty() {
        return map.isEmpty();
    }

    @Override
    public boolean containsKey(Object o) {
        return map.containsKey(o);
    }

    @Override
    public boolean containsValue(Object o) {
        return map.containsValue(o);
    }

    @Override
    public Object get(Object o) {
        return map.get(o);
    }

    @Override
    public Object put(String s, Object o) {
        if (o == null) {
            return map.remove(s);
        } else {
            return map.put(s, o);
        }
    }

    @Override
    public Object remove(Object o) {
        return map.remove(o);
    }

    @SuppressWarnings("NullableProblems")
    @Override
    public void putAll(Map<? extends String, ?> m) {
        if (m == null) {
            return;
        }
        for (String s : m.keySet()) {
            map.put(s, m.get(s));
        }
    }

    @Override
    public void clear() {
        map.clear();
    }

    @Override
    public Set<String> keySet() {
        return map.keySet();
    }

    @Override
    public Collection<Object> values() {
        return map.values();
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
        return map.entrySet();
    }

    @Override
    public String toString() {
        return map.toString();
    }

    @Override
    public int hashCode() {
        return map.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return map.equals(obj);
    }
}
