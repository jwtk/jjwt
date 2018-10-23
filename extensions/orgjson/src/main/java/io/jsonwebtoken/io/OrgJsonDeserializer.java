package io.jsonwebtoken.io;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @since 0.10.0
 */
public class OrgJsonDeserializer implements Deserializer<Object> {

    @SuppressWarnings("unchecked")
    @Override
    public Object deserialize(byte[] bytes) throws DeserializationException {

        Assert.notNull(bytes, "JSON byte array cannot be null");

        if (bytes.length == 0) {
            throw new DeserializationException("Invalid JSON: zero length byte array.");
        }

        try {
            String s = new String(bytes, Strings.UTF_8);
            return parse(s);
        } catch (Exception e) {
            String msg = "Invalid JSON: " + e.getMessage();
            throw new DeserializationException(msg, e);
        }
    }

    private Object parse(String json) throws JSONException {

        JSONTokener tokener = new JSONTokener(json);

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
        for( int i = 0; i < length; i++) {
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
}
