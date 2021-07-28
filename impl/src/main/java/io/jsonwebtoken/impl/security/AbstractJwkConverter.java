package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.MalformedKeyException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

abstract class AbstractJwkConverter<K extends Key> implements JwkConverter<K> {

    static void malformed(String msg) {
        throw new MalformedKeyException(msg);
    }

    protected static Map<String,?> sanitize(Map<String,?> jwk, String sensitiveKey) {
        //remove any sensitive value that may exist so we don't include it in the exception message
        //(which may be printed to logs or the console):
        Map<String,?> msgJwk = jwk;
        if (jwk.containsKey(sensitiveKey)) {
            Map<String,Object> sanitized = new LinkedHashMap<>(jwk);
            sanitized.put(sensitiveKey, "<redacted>");
            msgJwk = sanitized;
        }
        return msgJwk;
    }

    static String getRequiredString(Map<String, ?> m, String name) {
        Assert.notEmpty(m, "JWK map cannot be null or empty.");
        Object value = m.get(name);
        if (value == null) {
            malformed("JWK is missing required case-sensitive '" + name + "' member.");
        }
        String s = String.valueOf(value);
        if (!Strings.hasText(s)) {
            malformed("JWK '" + name + "' member cannot be null or empty.");
        }
        return s;
    }

    static BigInteger getRequiredBigInt(Map<String, ?> m, String name, boolean sensitive) {
        String s = getRequiredString(m, name);
        try {
            byte[] bytes = Decoders.BASE64URL.decode(s);
            return new BigInteger(1, bytes);
        } catch (Exception e) {
            String val = sensitive ? "<redacted>" : s;
            String msg = "Unable to decode JWK member '" + name + "' to BigInteger from value: " + val;
            throw new MalformedKeyException(msg, e);
        }
    }

    // Copied from Apache Commons Codec 1.14:
    // https://github.com/apache/commons-codec/blob/af7b94750e2178b8437d9812b28e36ac87a455f2/src/main/java/org/apache/commons/codec/binary/Base64.java#L746-L775
    static byte[] toUnsignedBytes(BigInteger bigInt) {
        final int bitlen = bigInt.bitLength();
        // round bitlen
        final int roundedBitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bitlen % 8) != 0) && (((bitlen / 8) + 1) == (roundedBitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bitlen % 8) == 0) {
            startSrc = 1;
            len--;
        }
        final int startDst = roundedBitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[roundedBitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }

    private final String keyType;

    AbstractJwkConverter(String keyType) {
        Assert.hasText(keyType, "keyType argument cannot be null or empty.");
        this.keyType = keyType;
    }

    @Override
    public String getId() {
        return this.keyType;
    }

    KeyFactory getKeyFactory() {
        return getKeyFactory(getId());
    }

    KeyFactory getKeyFactory(String alg) {
        try {
            return KeyFactory.getInstance(alg);
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to obtain JCA KeyFactory instance for algorithm: " + alg;
            throw new KeyException(msg, e);
        }
    }

    Map<String,String> newJwkMap() {
        Map<String,String> m = new HashMap<>();
        m.put("kty", getId());
        return m;
    }

}
