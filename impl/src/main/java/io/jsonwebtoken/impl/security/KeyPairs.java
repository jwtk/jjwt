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
