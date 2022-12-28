package io.jsonwebtoken.security;

import java.net.URI;

public interface JwkThumbprint {

    HashAlgorithm getHashAlgorithm();

    String toString();

    URI toURI();
}
