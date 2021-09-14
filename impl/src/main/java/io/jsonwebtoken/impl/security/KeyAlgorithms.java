package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.EncryptedKeyAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

//bridge class for the API so it doesn't need to know implementation/constructor argument details
public final class KeyAlgorithms {

    private static final String RSA1_5_ID = "RSA1_5";
    private static final String RSA1_5_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String RSA_OAEP_ID = "RSA-OAEP";
    private static final String RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String RSA_OAEP_256_ID = "RSA-OAEP-256";
    private static final String RSA_OAEP_256_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final AlgorithmParameterSpec RSA_OAEP_256_SPEC =
        new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    // prevent instantiation
    private KeyAlgorithms() {
    }

    public static KeyAlgorithm<SecretKey, SecretKey> direct() {
        return new DirectKeyAlgorithm();
    }

    public static EncryptedKeyAlgorithm<SecretKey, SecretKey> a128kw() {
        return new AesWrapKeyAlgorithm(128);
    }

    public static EncryptedKeyAlgorithm<SecretKey, SecretKey> a192kw() {
        return new AesWrapKeyAlgorithm(192);
    }

    public static EncryptedKeyAlgorithm<SecretKey, SecretKey> a256kw() {
        return new AesWrapKeyAlgorithm(256);
    }

    public static EncryptedKeyAlgorithm<SecretKey, SecretKey> a128gcmkw() {
        return new AesGcmKeyAlgorithm(128);
    }

    public static EncryptedKeyAlgorithm<SecretKey, SecretKey> a192gcmkw() {
        return new AesGcmKeyAlgorithm(192);
    }

    public static EncryptedKeyAlgorithm<SecretKey, SecretKey> a256gcmkw() {
        return new AesGcmKeyAlgorithm(256);
    }

    public static <EK extends RSAKey & PublicKey, DK extends RSAKey & PrivateKey> EncryptedKeyAlgorithm<EK, DK> rsa1_5() {
        return new DefaultRsaKeyAlgorithm<>(RSA1_5_ID, RSA1_5_TRANSFORMATION);
    }

    public static <EK extends RSAKey & PublicKey, DK extends RSAKey & PrivateKey> EncryptedKeyAlgorithm<EK, DK> rsaOaep() {
        return new DefaultRsaKeyAlgorithm<>(RSA_OAEP_ID, RSA_OAEP_TRANSFORMATION);
    }

    public static <EK extends RSAKey & PublicKey, DK extends RSAKey & PrivateKey> EncryptedKeyAlgorithm<EK, DK> rsaOaep256() {
        return new DefaultRsaKeyAlgorithm<>(RSA_OAEP_256_ID, RSA_OAEP_256_TRANSFORMATION, RSA_OAEP_256_SPEC);
    }

}
