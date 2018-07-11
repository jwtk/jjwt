package io.jsonwebtoken.io.impl.orgjson;

import io.jsonwebtoken.codec.Encoder;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONString;
import org.json.JSONWriter;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

public class OrgJsonSerializer<T> implements Serializer<T> {

    @Override
    public byte[] serialize(T t) throws SerializationException {
        try {
            Object o = toJSONInstance(t);
            return toBytes(o);
        } catch (SerializationException se) {
            //propagate
            throw se;
        } catch (Exception e) {
            String msg = "Unable to serialize object of type " + t.getClass().getName() + " to JSON: " + e.getMessage();
            throw new SerializationException(msg, e);
        }
    }

    private Object toJSONInstance(Object object) {

        if (object == null) {
            return JSONObject.NULL;
        }

        if (object instanceof JSONObject || object instanceof JSONArray
            || JSONObject.NULL.equals(object) || object instanceof JSONString
            || object instanceof Byte || object instanceof Character
            || object instanceof Short || object instanceof Integer
            || object instanceof Long || object instanceof Boolean
            || object instanceof Float || object instanceof Double
            || object instanceof String || object instanceof BigInteger
            || object instanceof BigDecimal || object instanceof Enum) {
            return object;
        }

        if (object instanceof Calendar) {
            object = ((Calendar)object).getTime(); //sets object to date, will be converted in next if-statement:
        }

        if (object instanceof Date) {
            Date date = (Date)object;
            return DateFormats.formatIso8601(date);
        }

        if (object instanceof byte[]) {
            return Encoder.BASE64.encode((byte[])object);
        }

        if (object instanceof char[]) {
            return new String((char[])object);
        }

        if (object instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) object;
            return toJSONObject(map);
        }
        if (object instanceof Collection) {
            Collection<?> coll = (Collection<?>) object;
            return toJSONArray(coll);
        }
        if (Objects.isArray(object)) {
            Collection c = Collections.arrayToList(object);
            return toJSONArray(c);
        }

        //not an immediately JSON-compatible object and probably a JavaBean (or similar).  We can't convert that
        //directly without using a marshaller of some sort:
        String msg = "Unable to serialize object of type " + object.getClass().getName() + " to JSON using known heuristics.";
        throw new SerializationException(msg);
    }

    private JSONObject toJSONObject(Map<?,?> m) {

        JSONObject obj = new JSONObject();

        for(Map.Entry<?,?> entry : m.entrySet()) {
            Object k = entry.getKey();
            Object value = entry.getValue();

            String key = String.valueOf(k);
            value = toJSONInstance(value);
            obj.put(key, value);
        }

        return obj;
    }

    private JSONArray toJSONArray(Collection c) {

        JSONArray array = new JSONArray();

        for(Object o : c) {
            o = toJSONInstance(o);
            array.put(o);
        }

        return array;
    }

    @SuppressWarnings("WeakerAccess") //for testing
    protected byte[] toBytes(Object o) {
        String s = JSONWriter.valueToString(o);
        return s.getBytes(Strings.UTF_8);
    }
}
