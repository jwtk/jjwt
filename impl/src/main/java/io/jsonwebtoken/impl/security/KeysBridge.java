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
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public final class KeysBridge {

    // prevent instantiation
    private KeysBridge() {
    }

    public static Password password(char[] password) {
        return new PasswordSpec(password);
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

    /**
     * Returns the specified key's key length (in bits) if possible, or {@code -1} if unable to determine the length.
     *
     * <p>Some KeyStore implementations - like Hardware Security Modules, PKCS11 key stores, and later versions
     * of Android - will not allow applications or libraries to determine a key's length.  In these cases,
     * this method will return {@code -1} to indicate the length could not be determined.</p>
     *
     * @param key the key to inspect
     * @return the specified key's key length in bits, or {@code -1} if unable to determine length.
     */
    public static int findBitLength(Key key) {
        if (key instanceof SecretKey) {
            SecretKey sk = (SecretKey) key;
            if ("RAW".equals(sk.getFormat())) {
                byte[] encoded = findEncoded(key);
                if (encoded != null) {
                    long len = Bytes.bitLength(encoded);
                    return Assert.lte(len, (long) Integer.MAX_VALUE, "Excessive key bit length.").intValue();
                }
            }
        } else if (key instanceof RSAKey) {
            return ((RSAKey) key).getModulus().bitLength();
        } else if (key instanceof ECKey) {
            return ((ECKey) key).getParams().getOrder().bitLength();
        } else {
            //try to see if Edwards key:
            EdwardsCurve curve = EdwardsCurve.findByKey(key);
            if (curve != null) {
                return curve.getKeyBitLength();
            }
        }
        return -1; // unable to determine
    }

    public static byte[] getEncoded(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        byte[] encoded = findEncoded(key);
        if (Bytes.isEmpty(encoded)) {
            String msg = key.getClass().getName() + " encoded bytes cannot be null or empty.";
            throw new UnsupportedKeyException(msg);
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
