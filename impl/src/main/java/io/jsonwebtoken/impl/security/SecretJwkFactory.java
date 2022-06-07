package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.RequiredFieldReader;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.MalformedKeyException;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.SecretKeySignatureAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
class SecretJwkFactory extends AbstractFamilyJwkFactory<SecretKey, SecretJwk> {

    private static final String ENCODED_UNAVAILABLE_MSG = "SecretKey argument does not have any encoded bytes, or " + "the key's backing JCA Provider is preventing key.getEncoded() from returning any bytes.  It is not " + "possible to represent the SecretKey instance as a JWK.";

    SecretJwkFactory() {
        super(DefaultSecretJwk.TYPE_VALUE, SecretKey.class);
    }

    static byte[] getRequiredEncoded(SecretKey key) {
        Assert.notNull(key, "SecretKey argument cannot be null.");
        byte[] encoded = null;
        Exception cause = null;
        try {
            encoded = key.getEncoded();
        } catch (Exception e) {
            cause = e;
        }

        if (Arrays.length(encoded) == 0) {
            throw new IllegalArgumentException(ENCODED_UNAVAILABLE_MSG, cause);
        }

        return encoded;
    }

    @Override
    protected SecretJwk createJwkFromKey(JwkContext<SecretKey> ctx) {
        SecretKey key = Assert.notNull(ctx.getKey(), "JwkContext key cannot be null.");
        String k;
        try {
            byte[] encoded = getRequiredEncoded(key);
            k = Encoders.BASE64URL.encode(encoded);
            Assert.hasText(k, "k value cannot be null or empty.");
        } catch (Exception e) {
            String msg = "Unable to encode SecretKey to JWK: " + e.getMessage();
            throw new UnsupportedKeyException(msg, e);
        }

        ctx.put(DefaultSecretJwk.K.getId(), k);

        return new DefaultSecretJwk(ctx);
    }

    private static void assertKeyBitLength(byte[] bytes, SecretKeySignatureAlgorithm alg) {
        long bitLen = Bytes.bitLength(bytes);
        long requiredBitLen = alg.getKeyBitLength();
        if (bitLen != requiredBitLen) {
            // Implementors note:  Don't print out any information about the `bytes` value itself - size,
            // content, etc, as it is considered secret material:
            String msg = "Secret JWK " + AbstractJwk.ALG + " value is '" + alg.getId() + "', but the " + DefaultSecretJwk.K + " length does not equal the '" + alg.getId() + "' length requirement of " + Bytes.bitsMsg(requiredBitLen) + ". This discrepancy could be the result of an algorithm " + "substitution attack or simply an erroneously constructed JWK. In either case, it is likely " + "to result in unexpected or undesired security consequences.";
            throw new MalformedKeyException(msg);
        }
    }

    @Override
    protected SecretJwk createJwkFromValues(JwkContext<SecretKey> ctx) {
        FieldReadable reader = new RequiredFieldReader(ctx);
        byte[] bytes = reader.get(DefaultSecretJwk.K);
        String jcaName = null;

        String id = ctx.getAlgorithm();
        if (Strings.hasText(id)) {
            SignatureAlgorithm<?, ?> alg = SignatureAlgorithmsBridge.findById(id);
            if (alg instanceof SecretKeySignatureAlgorithm) {
                jcaName = ((CryptoAlgorithm) alg).getJcaName(); // valid for all JJWT alg implementations
                Assert.hasText(jcaName, "Algorithm jcaName cannot be null or empty.");
                assertKeyBitLength(bytes, (SecretKeySignatureAlgorithm) alg);
            }
        }
        if (!Strings.hasText(jcaName) &&
                ("sig".equalsIgnoreCase(ctx.getPublicKeyUse()) || // [1]
                        (!Collections.isEmpty(ctx.getOperations()) && ctx.getOperations().contains("sign")))) { // [2]
            // [1] Even though 'use' is for PUBLIC KEY use (as defined in RFC 7515), RFC 7520 shows secret keys with
            //     'use' values, so we'll account for that as well
            //
            // [2] operations values are case-sensitive, so we don't need to test for upper/lowercase "sign" values

            // The only JWA SecretKey signature algorithms are HS256, HS384, HS512, so choose based on bit length:
            jcaName = "HmacSHA" + Bytes.bitLength(bytes);
        }
        if (jcaName == null) { // not an HS* algorithm, no signature "use", no "sign" key op, so default to encryption:
            jcaName = "AES";
        }

        SecretKey key = new SecretKeySpec(bytes, jcaName);
        ctx.setKey(key);
        return new DefaultSecretJwk(ctx);
    }
}
