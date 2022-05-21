package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Message;
import io.jsonwebtoken.security.Request;

/**
 * Request to perform a cryptographic operation on a byte array.
 */
public interface ContentRequest extends Message, Request {
}
