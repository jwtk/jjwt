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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

public final class KeyPairs {

    private KeyPairs() {
    }

    private static String familyPrefix(Class<?> clazz) {
        if (RSAKey.class.isAssignableFrom(clazz)) {
            return "RSA ";
        } else if (ECKey.class.isAssignableFrom(clazz)) {
            return "EC ";
        } else {
            return Strings.EMPTY;
        }
    }

    public static <K> K getKey(KeyPair pair, Class<K> clazz) {
        Assert.notNull(pair, "KeyPair cannot be null.");
        String prefix = familyPrefix(clazz) + "KeyPair ";
        boolean isPrivate = PrivateKey.class.isAssignableFrom(clazz);
        Key key = isPrivate ? pair.getPrivate() : pair.getPublic();
        return assertKey(key, clazz, prefix);
    }

    public static <K> K assertKey(Key key, Class<K> clazz, String msgPrefix) {
        Assert.notNull(key, "Key argument cannot be null.");
        Assert.notNull(clazz, "Class argument cannot be null.");
        String type = key instanceof PrivateKey ? "private" : "public";
        if (!clazz.isInstance(key)) {
            String msg = msgPrefix + type + " key must be an instance of " + clazz.getName() +
                ". Type found: " + key.getClass().getName();
            throw new IllegalArgumentException(msg);
        }
        return clazz.cast(key);
    }
}
