package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.MalformedKeyException;

import java.math.BigInteger;
import java.util.Map;

/**
 * Allows use af shared assertions across codebase, regardless of inheritance hierarchy.
 */
public class DefaultValueGetter implements ValueGetter {

    private final Map<String, ?> values;

    public DefaultValueGetter(Map<String, ?> values) {
        this.values = Assert.notEmpty(values, "Values cannot be null or empty.");
    }

    private String name() {
        if (values instanceof JweHeader) {
            return "JWE header";
        } else if (values instanceof JwsHeader) {
            return "JWS header";
        } else if (values instanceof Header) {
            return "JWT header";
        } else if (values instanceof Jwk || values instanceof JwkContext) {
            Object value = values.get(AbstractJwk.KTY.getId());
            if (DefaultSecretJwk.TYPE_VALUE.equals(value)) {
                value = "Secret";
            }
            return value instanceof String ? value + " JWK" : "JWK";
        } else {
            return "Map";
        }
    }

    private JwtException malformed(String msg) {
        if (values instanceof JwkContext || values instanceof Jwk) {
            return new MalformedKeyException(msg);
        } else {
            return new MalformedJwtException(msg);
        }
    }

    protected Object getRequiredValue(String key) {
        Object value = this.values.get(key);
        if (value == null) {
            String msg = name() + " is missing required '" + key + "' value.";
            throw malformed(msg);
        }
        return value;
    }

    @Override
    public String getRequiredString(String key) {
        Object value = getRequiredValue(key);
        if (!(value instanceof String)) {
            String msg = name() + " '" + key + "' value must be a String. Actual type: " + value.getClass().getName();
            throw malformed(msg);
        }
        String sval = Strings.clean((String) value);
        if (!Strings.hasText(sval)) {
            String msg = name() + " '" + key + "' string value cannot be null or empty.";
            throw malformed(msg);
        }
        return (String) value;
    }

    @Override
    public int getRequiredInteger(String key) {
        Object value = getRequiredValue(key);
        if (!(value instanceof Integer)) {
            String msg = name() + " '" + key + "' value must be an Integer. Actual type: " + value.getClass().getName();
            throw malformed(msg);
        }
        return (Integer) value;
    }

    @Override
    public int getRequiredPositiveInteger(String key) {
        int value = getRequiredInteger(key);
        if (value <= 0) {
            String msg = name() + " '" + key + "' value must be a positive Integer. Value: " + value;
            throw malformed(msg);
        }
        return value;
    }

    @Override
    public byte[] getRequiredBytes(String key) {

        String encoded = getRequiredString(key);

        byte[] decoded;
        try {
            decoded = Decoders.BASE64URL.decode(encoded);
        } catch (Exception e) {
            String msg = name() + " '" + key + "' value is not a valid Base64URL String: " + e.getMessage();
            throw malformed(msg);
        }

        if (Arrays.length(decoded) == 0) {
            String msg = name() + " '" + key + "' decoded byte array cannot be empty.";
            throw malformed(msg);
        }

        return decoded;
    }

    @Override
    public byte[] getRequiredBytes(String key, int requiredByteLength) {
        byte[] decoded = getRequiredBytes(key);
        int len = Arrays.length(decoded);
        if (len != requiredByteLength) {
            String msg = name() + " '" + key + "' decoded byte array must be " + Bytes.bytesMsg(requiredByteLength) +
                " long. Actual length: " + Bytes.bytesMsg(len) + ".";
            throw malformed(msg);
        }
        return decoded;
    }

    @Override
    public BigInteger getRequiredBigInt(String key, boolean sensitive) {
        String s = getRequiredString(key);
        try {
            byte[] bytes = Decoders.BASE64URL.decode(s);
            return new BigInteger(1, bytes);
        } catch (Exception e) {
            String msg = "Unable to decode " + name() + " '" + key + "' value";
            if (!sensitive) {
                msg += " '" + s + "'";
            }
            msg += " to BigInteger: " + e.getMessage();
            throw malformed(msg);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public Map<String, ?> getRequiredMap(String key) {
        Object value = getRequiredValue(key);
        if (!(value instanceof Map)) {
            String msg = name() + " '" + key + "' value must be a Map. Actual type: " + value.getClass().getName();
            throw malformed(msg);
        }
        return (Map<String,?>)value;
    }
}
