package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Jwk;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

abstract class AbstractFamilyJwkFactory<K extends Key, J extends Jwk<K>> implements FamilyJwkFactory<K, J> {

    // Copied from Apache Commons Codec 1.14:
    // https://github.com/apache/commons-codec/blob/af7b94750e2178b8437d9812b28e36ac87a455f2/src/main/java/org/apache/commons/codec/binary/Base64.java#L746-L775
    static byte[] toUnsignedBytes(BigInteger bigInt) {
        Assert.notNull(bigInt, "BigInteger argument cannot be null.");
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

    protected static String encode(BigInteger bigInt) {
        byte[] unsigned = toUnsignedBytes(bigInt);
        return Encoders.BASE64URL.encode(unsigned);
    }

    private final String ktyValue;
    private final Class<K> keyType;

    AbstractFamilyJwkFactory(String ktyValue, Class<K> keyType) {
        this.ktyValue = Assert.hasText(ktyValue, "keyType argument cannot be null or empty.");
        this.keyType = Assert.notNull(keyType, "keyType class cannot be null.");
    }

    @Override
    public String getId() {
        return this.ktyValue;
    }

    @Override
    public boolean supports(JwkContext<?> ctx) {
        return supportsKey(ctx.getKey()) || supportsKeyValues(ctx);
    }

    protected boolean supportsKeyValues(JwkContext<?> ctx) {
        return this.ktyValue.equals(ctx.getType());
    }

    protected boolean supportsKey(Key key) {
        return this.keyType.isInstance(key);
    }

    protected K generateKey(final JwkContext<K> ctx, final CheckedFunction<KeyFactory, K> fn) {
        return generateKey(ctx, this.keyType, fn);
    }

    protected <T extends Key> T generateKey(final JwkContext<?> ctx, final Class<T> type, final CheckedFunction<KeyFactory, T> fn) {
        return new JcaTemplate(getId(), ctx.getProvider()).execute(KeyFactory.class, new CheckedFunction<KeyFactory, T>() {
            @Override
            public T apply(KeyFactory instance) throws Exception {
                try {
                    return fn.apply(instance);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    String msg = "Unable to create " + type.getSimpleName() + " from JWK {" + ctx + "}: " + e.getMessage();
                    throw new InvalidKeyException(msg, e);
                }
            }
        });
    }

    @Override
    public final J createJwk(JwkContext<K> ctx) {
        Assert.notNull(ctx, "JwkContext argument cannot be null.");
        if (!supports(ctx)) { //should be asserted by caller, but assert just in case:
            String msg = "Unsupported JwkContext.";
            throw new IllegalArgumentException(msg);
        }
        K key = ctx.getKey();
        if (key != null) {
            ctx.setType(this.ktyValue);
            return createJwkFromKey(ctx);
        } else {
            return createJwkFromValues(ctx);
        }
    }

    //when called, ctx.getKey() is guaranteed to be non-null
    protected abstract J createJwkFromKey(JwkContext<K> ctx);

    //when called ctx.getType() is guaranteed to equal this.ktyValue
    protected abstract J createJwkFromValues(JwkContext<K> ctx);
}
