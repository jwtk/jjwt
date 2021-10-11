package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

public interface PbeKey extends SecretKey {

    char[] getPassword();

    int getWorkFactor();

}
