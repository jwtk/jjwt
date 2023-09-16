/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.SecretKeyBuilder;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.VerifySecureDigestRequest;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
final class DefaultMacAlgorithm extends AbstractSecureDigestAlgorithm<SecretKey, SecretKey> implements MacAlgorithm {

    private static final String HS256_OID = "1.2.840.113549.2.9";
    private static final String HS384_OID = "1.2.840.113549.2.10";
    private static final String HS512_OID = "1.2.840.113549.2.11";

    private static final Set<String> JWA_STANDARD_IDS = new LinkedHashSet<>(Collections.of("HS256", "HS384", "HS512"));

    static final DefaultMacAlgorithm HS256 = new DefaultMacAlgorithm(256);
    static final DefaultMacAlgorithm HS384 = new DefaultMacAlgorithm(384);
    static final DefaultMacAlgorithm HS512 = new DefaultMacAlgorithm(512);

    private static final Map<String, DefaultMacAlgorithm> JCA_NAME_MAP;

    static {
        JCA_NAME_MAP = new LinkedHashMap<>(6);

        // In addition to JCA names, PKCS12 OIDs are added to these per
        // https://bugs.openjdk.java.net/browse/JDK-8243551 as well:
        JCA_NAME_MAP.put(HS256.getJcaName().toUpperCase(Locale.ENGLISH), HS256); // for case-insensitive lookup
        JCA_NAME_MAP.put(HS256_OID, HS256);

        JCA_NAME_MAP.put(HS384.getJcaName().toUpperCase(Locale.ENGLISH), HS384);
        JCA_NAME_MAP.put(HS384_OID, HS384);

        JCA_NAME_MAP.put(HS512.getJcaName().toUpperCase(Locale.ENGLISH), HS512);
        JCA_NAME_MAP.put(HS512_OID, HS512);
    }

    private final int minKeyBitLength; //in bits

    private DefaultMacAlgorithm(int digestBitLength) {
        this("HS" + digestBitLength, "HmacSHA" + digestBitLength, digestBitLength);
    }

    DefaultMacAlgorithm(String id, String jcaName, int minKeyBitLength) {
        super(id, jcaName);
        Assert.isTrue(minKeyBitLength > 0, "minKeyLength must be greater than zero.");
        this.minKeyBitLength = minKeyBitLength;
    }

    @Override
    public int getKeyBitLength() {
        return this.minKeyBitLength;
    }

    private boolean isJwaStandard() {
        return JWA_STANDARD_IDS.contains(getId());
    }

    private static boolean isJwaStandardJcaName(String jcaName) {
        String key = jcaName.toUpperCase(Locale.ENGLISH);
        return JCA_NAME_MAP.containsKey(key);
    }

    static DefaultMacAlgorithm findByKey(Key key) {

        String alg = KeysBridge.findAlgorithm(key);
        if (!Strings.hasText(alg)) {
            return null;
        }

        String upper = alg.toUpperCase(Locale.ENGLISH);
        DefaultMacAlgorithm mac = JCA_NAME_MAP.get(upper);
        if (mac == null) {
            return null;
        }

        // even though we found a standard alg based on the JCA name, we need to confirm that the key length is
        // sufficient if the encoded key bytes are available:
        byte[] encoded = KeysBridge.findEncoded(key);
        long size = Bytes.bitLength(encoded);
        if (size >= mac.getKeyBitLength()) {
            return mac;
        }

        return null; // couldn't find a suitable match
    }


    @Override
    public SecretKeyBuilder key() {
        return new DefaultSecretKeyBuilder(getJcaName(), getKeyBitLength());
    }

    private void assertAlgorithmName(SecretKey key, boolean signing) {

        String name = key.getAlgorithm();
        if (!Strings.hasText(name)) {
            String msg = "The " + keyType(signing) + " key's algorithm cannot be null or empty.";
            throw new InvalidKeyException(msg);
        }

        // We can ignore PKCS11 key name assertions for two reasons:
        // 1. HSM module key algorithm names don't always align with JCA standard algorithm names, and
        // 2. Our KeysBridge.findBitLength implementation can extract the key length so we can still validate with that
        boolean pkcs11Key = KeysBridge.isSunPkcs11GenericSecret(key);

        //assert key's jca name is valid if it's a JWA standard algorithm:
        if (!pkcs11Key && isJwaStandard() && !isJwaStandardJcaName(name)) {
            throw new InvalidKeyException("The " + keyType(signing) + " key's algorithm '" + name +
                    "' does not equal a valid HmacSHA* algorithm name or PKCS12 OID and cannot be used with " +
                    getId() + ".");
        }
    }

    @Override
    protected void validateKey(Key k, boolean signing) {

        final String keyType = keyType(signing);
        if (k == null) {
            throw new IllegalArgumentException("MAC " + keyType + " key cannot be null.");
        }

        if (!(k instanceof SecretKey)) {
            String msg = "MAC " + keyType + " keys must be SecretKey instances.  Specified key is of type " +
                    k.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        if (k instanceof Password) {
            String msg = "Passwords are intended for use with key derivation algorithms only.";
            throw new InvalidKeyException(msg);
        }

        final SecretKey key = (SecretKey) k;

        final String id = getId();

        assertAlgorithmName(key, signing);

        int size = KeysBridge.findBitLength(key);

        // We can only perform length validation if key bit length is available
        // per https://github.com/jwtk/jjwt/issues/478 and https://github.com/jwtk/jjwt/issues/619
        // so return early if we can't:
        if (size < 0) return;

        if (size < this.minKeyBitLength) {
            String msg = "The " + keyType + " key's size is " + size + " bits which " +
                    "is not secure enough for the " + id + " algorithm.";

            if (isJwaStandard() && isJwaStandardJcaName(getJcaName())) { //JWA standard algorithm name - reference the spec:
                msg += " The JWT " +
                        "JWA Specification (RFC 7518, Section 3.2) states that keys used with " + id + " MUST have a " +
                        "size >= " + minKeyBitLength + " bits (the key size must be greater than or equal to the hash " +
                        "output size). Consider using the Jwts.SIG." + id + ".key() " +
                        "builder to create a key guaranteed to be secure enough for " + id + ".  See " +
                        "https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
            } else { //custom algorithm - just indicate required key length:
                msg += " The " + id + " algorithm requires keys to have a size >= " + minKeyBitLength + " bits.";
            }

            throw new WeakKeyException(msg);
        }
    }

    @Override
    public byte[] doDigest(final SecureRequest<byte[], SecretKey> request) {
        return jca(request).withMac(new CheckedFunction<Mac, byte[]>() {
            @Override
            public byte[] apply(Mac mac) throws Exception {
                mac.init(request.getKey());
                return mac.doFinal(request.getPayload());
            }
        });
    }

    protected boolean doVerify(VerifySecureDigestRequest<SecretKey> request) {
        byte[] providedSignature = request.getDigest();
        Assert.notEmpty(providedSignature, "Request signature byte array cannot be null or empty.");
        byte[] computedSignature = digest(request);
        return MessageDigest.isEqual(providedSignature, computedSignature);
    }
}
