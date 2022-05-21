package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Identifiable;

public interface HashAlgorithm extends Identifiable {

    byte[] hash(ContentRequest request);
}
