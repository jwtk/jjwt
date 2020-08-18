package io.jsonwebtoken.impl.lang;

import java.math.BigInteger;

public interface ValueGetter {

    String getRequiredString(String key);

    int getRequiredInteger(String key);

    int getRequiredPositiveInteger(String key);

    byte[] getRequiredBytes(String key);

    byte[] getRequiredBytes(String key, int requiredByteLength);

    BigInteger getRequiredBigInt(String key, boolean sensitive);
}
