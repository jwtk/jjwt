package io.jsonwebtoken.security;

import io.jsonwebtoken.Identifiable;

public interface HashAlgorithm extends Identifiable {

    byte[] hash(Request<byte[]> request);
}
