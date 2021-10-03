package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

import javax.crypto.interfaces.PBEKey;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

public final class DefaultPBEKey implements PBEKey {

    private static final String RAW_FORMAT = "RAW";

    private volatile boolean destroyed = false;
    private final char[] chars;
    private final byte[] bytes;
    private final int iterations;
    private final String algorithm;

    private static byte[] toBytes(char[] chars) {
        ByteBuffer buf = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] bytes = new byte[buf.limit()];
        buf.get(bytes);
        return bytes;
    }

    public DefaultPBEKey(char[] password, int iterations, String algorithm) {
        boolean empty = Objects.isEmpty(password);
        this.chars = empty ? new char[0] : password.clone();
        this.bytes = empty ? new byte[0] : toBytes(this.chars);
        if (iterations <= 0) {
            String msg = "Iterations must be an integer greater than zero. Value: " + iterations;
            throw new IllegalArgumentException(msg);
        }
        this.iterations = iterations;
        this.algorithm = Assert.hasText(algorithm, "Algorithm string cannot be null or empty.");
    }

    private void assertActive() {
        if (destroyed) {
            String msg = "PBKey has been destroyed. Password characters or bytes may not be obtained.";
            throw new IllegalStateException(msg);
        }
    }

    @Override
    public char[] getPassword() {
        assertActive();
        return this.chars.clone();
    }

    @Override
    public byte[] getSalt() {
        return null;
    }

    @Override
    public int getIterationCount() {
        return this.iterations;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getFormat() {
        return RAW_FORMAT;
    }

    @Override
    public byte[] getEncoded() {
        assertActive();
        return this.bytes.clone();
    }

    @Override
    public void destroy() {
        if (destroyed) return;
        java.util.Arrays.fill(bytes, (byte) 0);
        java.util.Arrays.fill(chars, '\u0000');
        this.destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
