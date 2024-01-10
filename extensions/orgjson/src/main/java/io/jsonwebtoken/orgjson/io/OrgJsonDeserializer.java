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
package io.jsonwebtoken.orgjson.io;

import io.jsonwebtoken.io.AbstractDeserializer;
import io.jsonwebtoken.lang.Assert;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.CharArrayReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @since 0.10.0
 */
public class OrgJsonDeserializer extends AbstractDeserializer<Object> {

    private final JSONTokenerFactory TOKENER_FACTORY;

    public OrgJsonDeserializer() {
        this(JSONTokenerFactory.INSTANCE);
    }

    private OrgJsonDeserializer(JSONTokenerFactory factory) {
        this.TOKENER_FACTORY = Assert.notNull(factory, "JSONTokenerFactory cannot be null.");
    }

    @Override
    protected Object doDeserialize(Reader reader) {
        return parse(reader);
    }

    private Object parse(Reader reader) throws JSONException {

        JSONTokener tokener = this.TOKENER_FACTORY.newTokener(reader);
        Assert.notNull(tokener, "JSONTokener cannot be null.");

        char c = tokener.nextClean(); //peak ahead
        tokener.back(); //revert

        if (c == '{') { //json object
            JSONObject o = new JSONObject(tokener);
            return toMap(o);
        } else if (c == '[') {
            JSONArray a = new JSONArray(tokener);
            return toList(a);
        } else {
            //raw json value
            Object value = tokener.nextValue();
            return convertIfNecessary(value);
        }
    }

    private Map<String, Object> toMap(JSONObject o) {
        Map<String, Object> map = new LinkedHashMap<>();
        // https://github.com/jwtk/jjwt/issues/380: use .keys() and *not* .keySet() for Android compatibility:
        Iterator<String> iterator = o.keys();
        while (iterator.hasNext()) {
            String key = iterator.next();
            Object value = o.get(key);
            value = convertIfNecessary(value);
            map.put(key, value);
        }
        return map;
    }

    private List<Object> toList(JSONArray a) {
        int length = a.length();
        List<Object> list = new ArrayList<>(length);
        // https://github.com/jwtk/jjwt/issues/380: use a.get(i) and *not* a.toList() for Android compatibility:
        for (int i = 0; i < length; i++) {
            Object value = a.get(i);
            value = convertIfNecessary(value);
            list.add(value);
        }
        return list;
    }

    private Object convertIfNecessary(Object v) {
        Object value = v;
        if (JSONObject.NULL.equals(value)) {
            value = null;
        } else if (value instanceof JSONArray) {
            value = toList((JSONArray) value);
        } else if (value instanceof JSONObject) {
            value = toMap((JSONObject) value);
        }
        return value;
    }

    /**
     * A factory to create {@link JSONTokener} instances from {@link Reader}s.
     *
     * @see <a href="https://github.com/jwtk/jjwt/issues/882">JJWT Issue 882</a>.
     * @since 0.12.4
     */
    static class JSONTokenerFactory { // package-protected on purpose. Not to be exposed as part of public API

        private static final Reader TEST_READER = new CharArrayReader("{}".toCharArray());

        private static final JSONTokenerFactory INSTANCE = new JSONTokenerFactory();

        private final boolean readerCtorAvailable;

        // package protected visibility for testing only:
        JSONTokenerFactory() {
            boolean avail = true;
            try {
                testTokener(TEST_READER);
            } catch (NoSuchMethodError err) {
                avail = false;
            }
            this.readerCtorAvailable = avail;
        }

        // visible for testing only
        protected void testTokener(@SuppressWarnings("SameParameterValue") Reader reader) throws NoSuchMethodError {
            new JSONTokener(reader);
        }

        /**
         * Reads all content from the specified reader and returns it as a single String.
         *
         * @param reader the reader to read characters from
         * @return the reader content as a single string
         */
        private static String toString(Reader reader) throws IOException {
            StringBuilder sb = new StringBuilder(4096);
            char[] buf = new char[4096];
            int n = 0;
            while (EOF != n) {
                n = reader.read(buf);
                if (n > 0) sb.append(buf, 0, n);
            }
            return sb.toString();
        }

        private JSONTokener newTokener(Reader reader) {
            if (this.readerCtorAvailable) {
                return new JSONTokener(reader);
            }
            // otherwise not available, likely Android or earlier org.json version, fall back to String ctor:
            String s;
            try {
                s = toString(reader);
            } catch (IOException ex) {
                String msg = "Unable to obtain JSON String from Reader: " + ex.getMessage();
                throw new JSONException(msg, ex);
            }
            return new JSONTokener(s);
        }
    }
}
