package io.jsonwebtoken.io;

import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.DateFormats;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

/**
 * @since 0.10.0
 */
public class OrgJsonSerializer<T> implements Serializer<T> {

    // we need reflection for these because of Android - see https://github.com/jwtk/jjwt/issues/388
    private static final String JSON_WRITER_CLASS_NAME = "org.json.JSONWriter";
    private static final Class[] VALUE_TO_STRING_ARG_TYPES = new Class[]{Object.class};
    private static final String JSON_STRING_CLASS_NAME = "org.json.JSONString";
    private static final Class JSON_STRING_CLASS;

    static { // see see https://github.com/jwtk/jjwt/issues/388
        if (Classes.isAvailable(JSON_STRING_CLASS_NAME)) {
            JSON_STRING_CLASS = Classes.forName(JSON_STRING_CLASS_NAME);
        } else {
            JSON_STRING_CLASS = null;
        }
    }

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

    /**
     * @since 0.10.5 see https://github.com/jwtk/jjwt/issues/388
     */
    private static boolean isJSONString(Object o) {
        if (JSON_STRING_CLASS != null) {
            return JSON_STRING_CLASS.isInstance(o);
        }
        return false;
    }

    private Object toJSONInstance(Object object) {

        if (object == null) {
            return JSONObject.NULL;
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

        if (object instanceof Calendar) {
            object = ((Calendar) object).getTime(); //sets object to date, will be converted in next if-statement:
        }

        if (object instanceof Date) {
            Date date = (Date) object;
            return DateFormats.formatIso8601(date);
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

    private JSONObject toJSONObject(Map<?, ?> m) {

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

    private JSONArray toJSONArray(Collection c) {

        JSONArray array = new JSONArray();

        for (Object o : c) {
            o = toJSONInstance(o);
            array.put(o);
        }

        return array;
    }

    @SuppressWarnings("WeakerAccess") //for testing
    protected byte[] toBytes(Object o) {
        String s;
        // https://github.com/jwtk/jjwt/issues/380 for Android compatibility (Android doesn't have org.json.JSONWriter):
        // This instanceof check is a sneaky (hacky?) heuristic: A JwtBuilder only ever provides Map<String,Object>
        // instances to its serializer instances, so by the time this method is invoked, 'o' will always be a
        // JSONObject.
        //
        // This is sufficient for all JJWT-supported scenarios on Android since Android users shouldn't ever use
        // JJWT's internal Serializer implementation for general JSON serialization.  That is, its intended use
        // is within the context of JwtBuilder execution and not for application use outside of that.
        if (o instanceof JSONObject) {
            s = o.toString();
        } else {
            // we still call JSONWriter for all other values 'just in case', and this works for all valid JSON values
            // This would fail on Android unless they include the newer org.json dependency and ignore Android's.
            s = Classes.invokeStatic(JSON_WRITER_CLASS_NAME, "valueToString", VALUE_TO_STRING_ARG_TYPES, o);
        }
        return s.getBytes(Strings.UTF_8);
    }
}
