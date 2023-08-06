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
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.security.PublicKey;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public final class KeysBridge {

    // prevent instantiation
    private KeysBridge() {
    }

    public static Password password(char[] password) {
        return new PasswordSpec(password);
    }

    public static byte[] findEncoded(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        byte[] encoded = null;
        try {
            encoded = key.getEncoded();
        } catch (Throwable ignored) {
        }
        return encoded;
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
