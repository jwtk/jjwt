package io.jsonwebtoken.security;

import javax.crypto.interfaces.PBEKey;

public interface PbeKeyBuilder<K extends PbeKey> {

    PbeKeyBuilder<K> forKey(PBEKey jcaKey);

    PbeKeyBuilder<K> setPassword(String password);

    PbeKeyBuilder<K> setPassword(char[] password);

    PbeKeyBuilder<K> setWorkFactor(int workFactor);

    K build();
}
