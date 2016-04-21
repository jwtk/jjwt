package io.jsonwebtoken;

import io.jsonwebtoken.impl.crypto.AesEncryptionAlgorithm;
import io.jsonwebtoken.impl.crypto.GcmAesEncryptionAlgorithm;
import io.jsonwebtoken.impl.crypto.HmacAesEncryptionAlgorithm;
import io.jsonwebtoken.lang.Collections;

import java.util.List;

public final class EncryptionAlgorithms {

    public static final HmacAesEncryptionAlgorithm A128CBC_HS256 =
            new HmacAesEncryptionAlgorithm(EncryptionAlgorithmName.A128CBC_HS256.getValue(), SignatureAlgorithm.HS256);

    public static final HmacAesEncryptionAlgorithm A192CBC_HS384 =
            new HmacAesEncryptionAlgorithm(EncryptionAlgorithmName.A192CBC_HS384.getValue(), SignatureAlgorithm.HS384);

    public static final HmacAesEncryptionAlgorithm A256CBC_HS512 =
            new HmacAesEncryptionAlgorithm(EncryptionAlgorithmName.A256CBC_HS512.getValue(), SignatureAlgorithm.HS512);

    public static final GcmAesEncryptionAlgorithm A128GCM =
            new GcmAesEncryptionAlgorithm(EncryptionAlgorithmName.A128GCM.getValue(), 16);

    public static final GcmAesEncryptionAlgorithm A192GCM =
            new GcmAesEncryptionAlgorithm(EncryptionAlgorithmName.A192GCM.getValue(), 24);

    public static final GcmAesEncryptionAlgorithm A256GCM =
            new GcmAesEncryptionAlgorithm(EncryptionAlgorithmName.A256GCM.getValue(), 32);

    public static List<? extends AesEncryptionAlgorithm> VALUES =
            Collections.of(A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM);
}
