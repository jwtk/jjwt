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

import io.jsonwebtoken.io.AbstractSerializer;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.lang.Supplier;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;

/**
 * @since 0.10.0
 */
public class OrgJsonSerializer<T> extends AbstractSerializer<T> {

    // we need reflection for these because of Android - see https://github.com/jwtk/jjwt/issues/388
    private static final String JSON_WRITER_CLASS_NAME = "org.json.JSONWriter";
    private static final Class<?>[] VALUE_TO_STRING_ARG_TYPES = new Class[]{Object.class};
    private static final String JSON_STRING_CLASS_NAME = "org.json.JSONString";
    private static final Class<?> JSON_STRING_CLASS;

    static { // see see https://github.com/jwtk/jjwt/issues/388
        if (Classes.isAvailable(JSON_STRING_CLASS_NAME)) {
            JSON_STRING_CLASS = Classes.forName(JSON_STRING_CLASS_NAME);
        } else {
            JSON_STRING_CLASS = null;
        }
    }

    @Override
    protected void doSerialize(T t, OutputStream out) throws Exception {
        Object o = toJSONInstance(t);
        String s = toString(o);
        byte[] bytes = Strings.utf8(s);
        out.write(bytes);
    }

    /**
     * @since 0.10.5 see https://github.com/jwtk/jjwt/issues/388
     */
    private static boolean isJSONString(Object o) {
        if (JSON_STRING_CLASS != null) {
            return JSON_STRING_CLASS.isInstance(o);
        }
        return false;
    }

    private Object toJSONInstance(Object object) throws IOException {

        if (object == null) {
            return JSONObject.NULL;
        }

        if (object instanceof Supplier) {
            object = ((Supplier<?>) object).get();
        }

        if (object instanceof JSONObject || object instanceof JSONArray
                || JSONObject.NULL.equals(object) || isJSONString(object)
                || object instanceof Byte || object instanceof Character
                || object instanceof Short || object instanceof Integer
                || object instanceof Long || object instanceof Boolean
                || object instanceof Float || object instanceof Double
                || object instanceof String || object instanceof BigInteger
                || object instanceof BigDecimal || object instanceof Enum) {
            return object;
        }

        if (object instanceof Instant) {
            return DateFormats.formatIso8601((Instant) object);
        }

        if (object instanceof byte[]) {
            return Encoders.BASE64.encode((byte[]) object);
        }

        if (object instanceof char[]) {
            return new String((char[]) object);
        }

        if (object instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) object;
            return toJSONObject(map);
        }

        if (Objects.isArray(object)) {
            object = Collections.arrayToList(object); //sets object to List, will be converted in next if-statement:
        }

        if (object instanceof Collection) {
            Collection<?> coll = (Collection<?>) object;
            return toJSONArray(coll);
        }

        //not an immediately JSON-compatible object and probably a JavaBean (or similar).  We can't convert that
        //directly without using a marshaller of some sort:
        String msg = "Unable to serialize object of type " + object.getClass().getName() + " to JSON using known heuristics.";
        throw new IOException(msg);
    }

    private JSONObject toJSONObject(Map<?, ?> m) throws IOException {

        JSONObject obj = new JSONObject();

        for (Map.Entry<?, ?> entry : m.entrySet()) {
            Object k = entry.getKey();
            Object value = entry.getValue();

            String key = String.valueOf(k);
            value = toJSONInstance(value);
            obj.put(key, value);
        }

        return obj;
    }

    private JSONArray toJSONArray(Collection<?> c) throws IOException {

        JSONArray array = new JSONArray();

        for (Object o : c) {
            o = toJSONInstance(o);
            array.put(o);
        }

        return array;
    }

    /**
     * Serializes the specified org.json instance a JSON String.
     *
     * @param o the org.json instance to convert to a String
     * @return the JSON String
     */
    protected String toString(Object o) {
        // https://github.com/jwtk/jjwt/issues/380 for Android compatibility (Android doesn't have org.json.JSONWriter):
        // This instanceof check is a sneaky (hacky?) heuristic: A JwtBuilder only ever provides Map<String,Object>
        // instances to its serializer instances, so by the time this method is invoked, 'o' will always be a
        // JSONObject.
        //
        // This is sufficient for all JJWT-supported scenarios on Android since Android users shouldn't ever use
        // JJWT's internal Serializer implementation for general JSON serialization.  That is, its intended use
        // is within the context of JwtBuilder execution and not for application use beyond that.
        if (o instanceof JSONObject) {
            return o.toString();
        }
        // we still call JSONWriter for all other values 'just in case', and this works for all valid JSON values
        // This would fail on Android unless they include the newer org.json dependency and ignore Android's.
        return Classes.invokeStatic(JSON_WRITER_CLASS_NAME, "valueToString", VALUE_TO_STRING_ARG_TYPES, o);
    }

    /**
     * Serializes the specified org.json instance a byte array.
     *
     * @param o the org.json instance to serialize
     * @return the JSON byte array
     * @deprecated not called by JJWT
     */
    @Deprecated
    protected byte[] toBytes(Object o) {
        String s = toString(o);
        return Strings.utf8(s);
    }
}
