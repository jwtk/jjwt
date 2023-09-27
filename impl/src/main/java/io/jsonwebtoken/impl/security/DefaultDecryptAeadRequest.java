package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptAeadRequest;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;

public class DefaultDecryptAeadRequest extends DefaultAeadRequest implements DecryptAeadRequest {

    private final byte[] TAG;

    public DefaultDecryptAeadRequest(InputStream payload, OutputStream out, SecretKey key, byte[] aad, byte[] iv, byte[] tag) {
        super(payload, out, null, null, key, aad,
                Assert.notEmpty(iv, "Initialization Vector cannot be null or empty."));
        this.TAG = Assert.notEmpty(tag, "AAD Authentication Tag cannot be null or empty.");
    }

    @Override
    public byte[] getDigest() {
        return this.TAG;
    }
}
