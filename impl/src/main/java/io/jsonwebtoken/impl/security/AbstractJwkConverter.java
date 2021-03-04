package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.MalformedKeyException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

abstract class AbstractJwkConverter implements JwkConverter {

    private static Map<String, ?> assertNotEmpty(Map<String, ?> m) {
        if (m == null || m.isEmpty()) {
            throw new InvalidKeyException("JWK map cannot be null or empty.");
        }
        return m;
    }

    static void malformed(String msg) {
        throw new MalformedKeyException(msg);
    }

    static String getRequiredString(Map<String, ?> m, String name) {
        assertNotEmpty(m);
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

    static BigInteger getRequiredBigInt(Map<String, ?> m, String name) {
        String s = getRequiredString(m, name);
        try {
            byte[] bytes = Decoders.BASE64URL.decode(s);
            return new BigInteger(bytes);
        } catch (Exception e) {
            String msg = "Unable to decode JWK member '" + name + "' to integer from value: " + s;
            throw new MalformedKeyException(msg, e);
        }
    }

    // Copied from Apache Commons Codec 1.14:
    // https://github.com/apache/commons-codec/blob/af7b94750e2178b8437d9812b28e36ac87a455f2/src/main/java/org/apache/commons/codec/binary/Base64.java#L746-L775
    static byte[] toUnsignedBytes(BigInteger bigInt) {
        int bitlen = bigInt.bitLength();
        // round bitlen
        bitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bigInt.bitLength() % 8) == 0) {
            startSrc = 1;
            len--;
        }
        final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[bitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }

    KeyFactory getKeyFactory(String alg) {
        try {
            return KeyFactory.getInstance(alg);
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to obtain JCA KeyFactory instance for algorithm: " + alg;
            throw new KeyException(msg, e);
        }
    }

}
