package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyResult;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class DefaultKeyResult implements KeyResult {

    private static final byte[] EMPTY_BYTES = new byte[0];

    private final byte[] payload;
    private final SecretKey key;
    private final Map<String, ?> headerParams;

    public DefaultKeyResult(SecretKey key) {
        this(EMPTY_BYTES, key);
    }

    public DefaultKeyResult(byte[] encryptedKey, SecretKey key) {
        this(encryptedKey, key, Collections.<String, Object>emptyMap());
    }

    public DefaultKeyResult(byte[] encryptedKey, SecretKey key, Map<String, ?> headerParams) {
        this.payload = Assert.notNull(encryptedKey, "encryptedKey cannot be null (but can be empty).");
        this.key = Assert.notNull(key, "Key argument cannot be null.");
        Assert.notNull(headerParams, "headerParams cannot be null.");
        this.headerParams = Collections.unmodifiableMap(new LinkedHashMap<>(headerParams));
    }

    @Override
    public byte[] getPayload() {
        return this.payload;
    }

    @Override
    public SecretKey getKey() {
        return this.key;
    }

    @Override
    public Map<String, ?> getHeaderParams() {
        return this.headerParams;
    }
}
