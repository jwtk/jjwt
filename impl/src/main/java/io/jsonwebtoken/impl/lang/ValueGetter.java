package io.jsonwebtoken.impl.lang;

import java.math.BigInteger;
import java.util.Map;

public interface ValueGetter {

    String getRequiredString(String key);

    int getRequiredInteger(String key);

    int getRequiredPositiveInteger(String key);

    byte[] getRequiredBytes(String key);

    byte[] getRequiredBytes(String key, int requiredByteLength);

    BigInteger getRequiredBigInt(String key, boolean sensitive);

    Map<String,?> getRequiredMap(String key);
}
