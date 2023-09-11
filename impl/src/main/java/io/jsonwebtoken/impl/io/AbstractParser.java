package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.lang.Assert;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.Map;

public abstract class AbstractParser<T> implements Parser<T> {

    protected final Provider provider;

    protected final Deserializer<?> deserializer;

    public AbstractParser(Provider provider, Deserializer<?> deserializer) {
        this.provider = provider;
        this.deserializer = Assert.notNull(deserializer, "Deserializer cannot be null.");
    }

    private Map<String, ?> deserialize(String json) {
        Assert.hasText(json, "JSON string cannot be null or empty.");
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        try {
            return deserialize(data);
        } catch (JwtException j) {
            throw j; // propagate
        } catch (Throwable t) {
            String msg = "Unable to deserialize JSON: " + t.getMessage();
            throw new DeserializationException(msg, t);
        }
    }

    @SuppressWarnings("unchecked")
    protected Map<String, ?> deserialize(byte[] data) {
        Object val = this.deserializer.deserialize(data);
        if (val == null) {
            String msg = "Deserialized data resulted in a null value; cannot create Map<String,?>";
            throw new DeserializationException(msg);
        }
        if (!(val instanceof Map)) {
            String msg = "Deserialized data is not a JSON Object; cannot create Map<String,?>";
            throw new DeserializationException(msg);
        }
        // JSON Specification requires all JSON Objects to have string-only keys.  So instead of
        // checking that the val.keySet() has all Strings, we blindly cast to a Map<String,?>
        // since input would rarely, if ever have non-string keys.  Even if it did, the resulting
        // ClassCastException would be caught by the calling deserialize(String) method above.
        return (Map<String, ?>) val;
    }

    @Override

    public final T parse(String input) {
        Map<String, ?> m = deserialize(input);
        return convert(m);
    }

    protected abstract T convert(Map<String, ?> m);

}
