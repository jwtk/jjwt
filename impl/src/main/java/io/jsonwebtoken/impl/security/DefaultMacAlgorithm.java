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
import io.jsonwebtoken.security.SecretKeyBuilder;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultMacAlgorithm extends AbstractSecureDigestAlgorithm<SecretKey, SecretKey> implements MacAlgorithm {

    private final int minKeyBitLength; //in bits

    private static final Set<String> JWA_STANDARD_IDS = new LinkedHashSet<>(Collections.of("HS256", "HS384", "HS512"));

    // PKCS12 OIDs are added to these lists per https://bugs.openjdk.java.net/browse/JDK-8243551
    private static final Set<String> HS256_JCA_NAMES = new LinkedHashSet<>(Collections.of("HMACSHA256", "1.2.840.113549.2.9"));
    private static final Set<String> HS384_JCA_NAMES = new LinkedHashSet<>(Collections.of("HMACSHA384", "1.2.840.113549.2.10"));
    private static final Set<String> HS512_JCA_NAMES = new LinkedHashSet<>(Collections.of("HMACSHA512", "1.2.840.113549.2.11"));

    private static final Set<String> VALID_HS256_JCA_NAMES;
    private static final Set<String> VALID_HS384_JCA_NAMES;

    static {
        VALID_HS384_JCA_NAMES = new LinkedHashSet<>(HS384_JCA_NAMES);
        VALID_HS384_JCA_NAMES.addAll(HS512_JCA_NAMES);
        VALID_HS256_JCA_NAMES = new LinkedHashSet<>(HS256_JCA_NAMES);
        VALID_HS256_JCA_NAMES.addAll(VALID_HS384_JCA_NAMES);
    }

    public DefaultMacAlgorithm(int digestBitLength) {
        this("HS" + digestBitLength, "HmacSHA" + digestBitLength, digestBitLength);
    }

    public DefaultMacAlgorithm(String id, String jcaName, int minKeyBitLength) {
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

    private boolean isJwaStandardJcaName(String jcaName) {
        return VALID_HS256_JCA_NAMES.contains(jcaName.toUpperCase(Locale.ENGLISH));
    }

    @Override
    public SecretKeyBuilder keyBuilder() {
        return new DefaultSecretKeyBuilder(getJcaName(), getKeyBitLength());
    }

    @Override
    protected void validateKey(Key k, boolean signing) {

        final String keyType = keyType(signing);

        if (k == null) {
            throw new IllegalArgumentException("Signature " + keyType + " key cannot be null.");
        }

        if (!(k instanceof SecretKey)) {
            String msg = "MAC " + keyType(signing) + " keys must be SecretKey instances.  Specified key is of type " +
                    k.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        final SecretKey key = (SecretKey) k;

        final String id = getId();

        String alg = key.getAlgorithm();
        if (!Strings.hasText(alg)) {
            String msg = "The " + keyType + " key's algorithm cannot be null or empty.";
            throw new InvalidKeyException(msg);
        }

        //assert key's jca name is valid if it's a JWA standard algorithm:
        if (isJwaStandard() && !isJwaStandardJcaName(alg)) {
            throw new InvalidKeyException("The " + keyType + " key's algorithm '" + alg + "' does not equal a valid " +
                    "HmacSHA* algorithm name or PKCS12 OID and cannot be used with " + id + ".");
        }

        byte[] encoded = null;

        // https://github.com/jwtk/jjwt/issues/478
        //
        // Some KeyStore implementations (like Hardware Security Modules and later versions of Android) will not allow
        // applications or libraries to obtain the secret key's encoded bytes.  In these cases, key length assertions
        // cannot be made, so we'll need to skip the key length checks if so.
        try {
            encoded = key.getEncoded();
        } catch (Exception ignored) {
        }

        // We can only perform length validation if key.getEncoded() is not null or does not throw an exception
        // per https://github.com/jwtk/jjwt/issues/478 and https://github.com/jwtk/jjwt/issues/619
        // so return early if we can't:
        if (encoded == null) return;

        int size = (int) Bytes.bitLength(encoded);
        if (size < this.minKeyBitLength) {
            String msg = "The " + keyType + " key's size is " + size + " bits which " +
                    "is not secure enough for the " + id + " algorithm.";

            if (isJwaStandard() && isJwaStandardJcaName(getJcaName())) { //JWA standard algorithm name - reference the spec:
                msg += " The JWT " +
                        "JWA Specification (RFC 7518, Section 3.2) states that keys used with " + id + " MUST have a " +
                        "size >= " + minKeyBitLength + " bits (the key size must be greater than or equal to the hash " +
                        "output size). Consider using the JwsAlgorithms." + id + ".keyBuilder() " +
                        "method to create a key guaranteed to be secure enough for " + id + ".  See " +
                        "https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
            } else { //custom algorithm - just indicate required key length:
                msg += " The " + id + " algorithm requires keys to have a size >= " + minKeyBitLength + " bits.";
            }

            throw new WeakKeyException(msg);
        }
    }

    @Override
    public byte[] doDigest(final SecureRequest<byte[], SecretKey> request) {
        return execute(request, Mac.class, new CheckedFunction<Mac, byte[]>() {
            @Override
            public byte[] apply(Mac mac) throws Exception {
                mac.init(request.getKey());
                return mac.doFinal(request.getPayload());
            }
        });
    }
}
