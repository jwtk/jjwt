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

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.Keys implementation
public final class KeysBridge {

    // prevent instantiation
    private KeysBridge() {
    }

    public static Password forPassword(char[] password) {
        return new PasswordSpec(password);
    }

    public static byte[] findEncoded(Key key) {
        if (key != null) {
            try {
                return key.getEncoded();
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    public static byte[] getEncoded(Key key) {
        byte[] encoded = findEncoded(key);
        if (Bytes.isEmpty(encoded)) {
            String msg = typeName(key) + " encoded bytes cannot be null or empty.";
            throw new UnsupportedKeyException(msg);
        }
        return encoded;
    }

    public static String typeName(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        if (key instanceof Password) {
            return Password.class.getSimpleName();
        } else if (key instanceof SecretKey) {
            return SecretKey.class.getSimpleName();
        } else if (key instanceof PublicKey) {
            return PublicKey.class.getSimpleName();
        } else if (key instanceof PrivateKey) {
            return PrivateKey.class.getSimpleName();
        }
        return key.getClass().getSimpleName();
    }
}
