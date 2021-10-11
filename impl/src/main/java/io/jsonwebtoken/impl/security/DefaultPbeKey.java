package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.PbeKey;

public class DefaultPbeKey implements PbeKey {

    private static final String RAW_FORMAT = "RAW";
    private static final String NONE_ALGORITHM = "NONE";

    private volatile boolean destroyed = false;
    private final char[] chars;
    //private final byte[] bytes;
    private final int workFactor;

//    private static byte[] toBytes(char[] chars) {
//        ByteBuffer buf = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
//        byte[] bytes = new byte[buf.limit()];
//        buf.get(bytes);
//        return bytes;
//    }

    public DefaultPbeKey(char[] password, int workFactor) {
        boolean empty = Objects.isEmpty(password);
        this.chars = empty ? new char[0] : password.clone();
        //this.bytes = empty ? new byte[0] : toBytes(this.chars);
        if (workFactor < 0) {
            String msg = "workFactor cannot be negative. Value: " + workFactor;
            throw new IllegalArgumentException(msg);
        }
        this.workFactor = workFactor;
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
    public int getWorkFactor() {
        return this.workFactor;
    }

    @Override
    public String getAlgorithm() {
        return NONE_ALGORITHM;
    }

    @Override
    public String getFormat() {
        return RAW_FORMAT;
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("getEncoded is not supported for PbeKey instances.");
        //assertActive();
        //return this.bytes.clone();
    }

    @Override
    public void destroy() {
//        if (bytes != null) {
//            java.util.Arrays.fill(bytes, (byte) 0);
//        }
        if (chars != null) {
            java.util.Arrays.fill(chars, '\u0000');
        }
        this.destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(this.chars);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof DefaultPbeKey) {
            DefaultPbeKey other = (DefaultPbeKey) obj;
            return this.workFactor == other.workFactor &&
                Objects.nullSafeEquals(this.chars, other.chars);
        }
        return false;
    }

    @Override
    public String toString() {
        return "password=<redacted>, workFactor=" + this.workFactor;
    }
}
