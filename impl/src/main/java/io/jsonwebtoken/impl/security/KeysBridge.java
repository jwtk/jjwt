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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeySupplier;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.PrivateKeyBuilder;
import io.jsonwebtoken.security.SecretKeyBuilder;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public final class KeysBridge {

     // Some HSMs use generic secrets. This prefix matches the generic secret algorithm name
     // used by SUN PKCS#11 provider, AWS CloudHSM JCE provider and possibly other HSMs
    private static final String GENERIC_SECRET_ALG_PREFIX = "Generic";

    // prevent instantiation
    private KeysBridge() {
    }

    public static Password password(char[] password) {
        return new PasswordSpec(password);
    }

    public static SecretKeyBuilder builder(SecretKey key) {
        return new ProvidedSecretKeyBuilder(key);
    }

    public static PrivateKeyBuilder builder(PrivateKey key) {
        return new ProvidedPrivateKeyBuilder(key);
    }

    /**
     * If the specified {@code key} is a {@link KeySupplier}, the 'root' (lowest level) key that may exist in
     * a {@code KeySupplier} chain is returned, otherwise the {@code key} is returned.
     *
     * @param key the key to check if it is a {@code KeySupplier}
     * @param <K> the key type
     * @return the lowest-level/root key available.
     */
    @SuppressWarnings("unchecked")
    public static <K extends Key> K root(K key) {
        return (key instanceof KeySupplier<?>) ? (K) root((KeySupplier<?>) key) : key;
    }

    public static <K extends Key> K root(KeySupplier<K> supplier) {
        Assert.notNull(supplier, "KeySupplier canot be null.");
        return Assert.notNull(root(supplier.getKey()), "KeySupplier key cannot be null.");
    }

    public static String findAlgorithm(Key key) {
        return key != null ? Strings.clean(key.getAlgorithm()) : null;
    }

    /**
     * Returns the specified key's available encoded bytes, or {@code null} if not available.
     *
     * <p>Some KeyStore implementations - like Hardware Security Modules, PKCS11 key stores, and later versions
     * of Android - will not allow applications or libraries to obtain a key's encoded bytes.  In these cases,
     * this method will return null.</p>
     *
     * @param key the key to inspect
     * @return the specified key's available encoded bytes, or {@code null} if not available.
     */
    public static byte[] findEncoded(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        byte[] encoded = null;
        try {
            encoded = key.getEncoded();
        } catch (Throwable ignored) {
        }
        return encoded;
    }

    public static boolean isGenericSecret(Key key) {
        if (!(key instanceof SecretKey)) {
            return false;
        }

        String algName = Assert.hasText(key.getAlgorithm(), "Key algorithm cannot be null or empty.");
        return algName.startsWith(GENERIC_SECRET_ALG_PREFIX);
    }

    /**
     * Returns the specified key's key length (in bits) if possible, or {@code -1} if unable to determine the length.
     *
     * @param key the key to inspect
     * @return the specified key's key length in bits, or {@code -1} if unable to determine length.
     */
    public static int findBitLength(Key key) {

        int bitlen = -1;

        // try to parse the length from key specification
        if (key instanceof SecretKey) {
            SecretKey secretKey = (SecretKey) key;
            if ("RAW".equals(secretKey.getFormat())) {
                byte[] encoded = findEncoded(secretKey);
                if (!Bytes.isEmpty(encoded)) {
                    bitlen = (int) Bytes.bitLength(encoded);
                    Bytes.clear(encoded);
                }
            }
        } else if (key instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) key;
            bitlen = rsaKey.getModulus().bitLength();
        } else if (key instanceof ECKey) {
            ECKey ecKey = (ECKey) key;
            bitlen = ecKey.getParams().getOrder().bitLength();
        } else {
            // We can check additional logic for EdwardsCurve even if the current JDK version doesn't support it:
            EdwardsCurve curve = EdwardsCurve.findByKey(key);
            if (curve != null) bitlen = curve.getKeyBitLength();
        }

        return bitlen;
    }

    public static byte[] getEncoded(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        byte[] encoded;
        try {
            encoded = key.getEncoded();
        } catch (Throwable t) {
            String msg = "Cannot obtain required encoded bytes from key [" + KeysBridge.toString(key) + "]: " +
                    t.getMessage();
            throw new InvalidKeyException(msg, t);
        }
        if (Bytes.isEmpty(encoded)) {
            String msg = "Missing required encoded bytes for key [" + toString(key) + "].";
            throw new InvalidKeyException(msg);
        }
        return encoded;
    }

    public static String toString(Key key) {
        if (key == null) {
            return "null";
        }
        if (key instanceof PublicKey) {
            return key.toString(); // safe to show internal key state as it's a public key
        }
        // else secret or private key, don't show internal key state, just public attributes
        return "class: " + key.getClass().getName() +
                ", algorithm: " + key.getAlgorithm() +
                ", format: " + key.getFormat();
    }
}
