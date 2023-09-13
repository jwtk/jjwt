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
import io.jsonwebtoken.impl.lang.OptionalMethodInvoker;
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

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public final class KeysBridge {

    private static final String SUNPKCS11_GENERIC_SECRET_CLASSNAME = "sun.security.pkcs11.P11Key$P11SecretKey";
    private static final String SUNPKCS11_GENERIC_SECRET_ALGNAME = "Generic Secret"; // https://github.com/openjdk/jdk/blob/4f90abaf17716493bad740dcef76d49f16d69379/src/jdk.crypto.cryptoki/share/classes/sun/security/pkcs11/P11KeyStore.java#L1292

    private static final String SUN_KEYUTIL_CLASSNAME = "sun.security.util.KeyUtil";
    private static final OptionalMethodInvoker<Key, Integer> SUN_KEYSIZE =
            new OptionalMethodInvoker<>(SUN_KEYUTIL_CLASSNAME, "getKeySize", Key.class, true);
    private static final String SUN_KEYUTIL_ERR = "Unexpected " + SUN_KEYUTIL_CLASSNAME + " invocation error.";

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

    public static boolean isSunPkcs11GenericSecret(Key key) {
        return key instanceof SecretKey &&
                key.getClass().getName().equals(SUNPKCS11_GENERIC_SECRET_CLASSNAME) &&
                SUNPKCS11_GENERIC_SECRET_ALGNAME.equals(key.getAlgorithm());
    }

    /**
     * Returns the specified key's key length (in bits) if possible, or {@code -1} if unable to determine the length.
     *
     * @param key the key to inspect
     * @return the specified key's key length in bits, or {@code -1} if unable to determine length.
     */
    public static int findBitLength(Key key) {

        Integer retval = SUN_KEYSIZE.apply(key);
        int bitlen = Assert.stateNotNull(retval, SUN_KEYUTIL_ERR);

        // SunPKCS11 SecretKey lengths are unfortunately reported in bytes, not bits
        // per https://bugs.openjdk.org/browse/JDK-8163173
        // (they should be multiplying the PKCS11 CKA_VALUE_LEN value by 8 since their own
        // sun.security.util.Length#getLength() JavaDoc states that values are intended to be in bits, not bytes)
        // So we account for that here:
        if (bitlen > 0 && isSunPkcs11GenericSecret(key)) {
            bitlen *= Byte.SIZE;
        }

        if (bitlen > 0) return bitlen;

        // We can check additional logic for EdwardsCurve even if the current JDK version doesn't support it:
        EdwardsCurve curve = EdwardsCurve.findByKey(key);
        if (curve != null) bitlen = curve.getKeyBitLength();

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
