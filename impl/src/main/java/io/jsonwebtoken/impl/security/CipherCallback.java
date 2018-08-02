package io.jsonwebtoken.impl.security;

import javax.crypto.Cipher;

public interface CipherCallback<T> {

    T doWithCipher(Cipher cipher) throws Exception;
}
