package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureRequest;
import io.jsonwebtoken.security.SecretKeySignatureAlgorithm;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

@SuppressWarnings("unused") //used via reflection in the io.jsonwebtoken.security.SignatureAlgorithms class
public class MacSignatureAlgorithm extends AbstractSignatureAlgorithm<SecretKey, SecretKey> implements SecretKeySignatureAlgorithm {

    private final int minKeyLength; //in bits

    private static final Set<String> JWA_STANDARD_IDS = new LinkedHashSet<>(Collections.of("HS256", "HS384", "HS512"));

    // PKCS12 OIDs are added to these lists per https://bugs.openjdk.java.net/browse/JDK-8243551
    private static final Set<String> HS256_JCA_NAMES = new LinkedHashSet<>(Collections.of("HMACSHA256", "1.2.840.113549.2.9"));
    private static final Set<String> HS384_JCA_NAMES = new LinkedHashSet<>(Collections.of("HMACSHA384", "1.2.840.113549.2.10"));
    private static final Set<String> HS512_JCA_NAMES = new LinkedHashSet<>(Collections.of("HMACSHA512", "1.2.840.113549.2.11"));

    private static final Set<String> VALID_HS256_JCA_NAMES;
    private static final Set<String> VALID_HS384_JCA_NAMES;

    static {
        VALID_HS384_JCA_NAMES = new LinkedHashSet<>(HS384_JCA_NAMES);
        VALID_HS384_JCA_NAMES.addAll(HS512_JCA_NAMES);
        VALID_HS256_JCA_NAMES = new LinkedHashSet<>(HS256_JCA_NAMES);
        VALID_HS256_JCA_NAMES.addAll(VALID_HS384_JCA_NAMES);
    }

    public MacSignatureAlgorithm(String id, String jcaName, int minKeyLength) {
        super(id, jcaName);
        Assert.isTrue(minKeyLength > 0, "minKeyLength must be greater than zero.");
        this.minKeyLength = minKeyLength;
    }

    int getMinKeyLength() {
        return this.minKeyLength;
    }

    private boolean isJwaStandard() {
        return JWA_STANDARD_IDS.contains(getId());
    }

    private boolean isJwaStandardJcaName(String jcaName) {
        return VALID_HS256_JCA_NAMES.contains(jcaName.toUpperCase(Locale.ENGLISH));
    }

    @Override
    public SecretKey generateKey() {
        return new JcaTemplate(getJcaName(), null).generateSecretKey(minKeyLength);
    }

    @Override
    protected void validateKey(Key k, boolean signing) {

        final String keyType = keyType(signing);

        if (k == null) {
            throw new IllegalArgumentException("Signature " + keyType + " key cannot be null.");
        }

        if (!(k instanceof SecretKey)) {
            String msg = "MAC " + keyType(signing) + " keys must be SecretKey instances.  Specified key is of type " +
                k.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        final SecretKey key = (SecretKey) k;

        final String id = getId();

        String alg = key.getAlgorithm();
        if (!Strings.hasText(alg)) {
            String msg = "The " + keyType + " key's algorithm cannot be null or empty.";
            throw new InvalidKeyException(msg);
        }

        //assert key's jca name is valid if it's a JWA standard algorithm:
        if (isJwaStandard() && !isJwaStandardJcaName(alg)) {
            throw new InvalidKeyException("The " + keyType + " key's algorithm '" + alg + "' does not equal a valid " +
                "HmacSHA* algorithm name or PKCS12 OID and cannot be used with " + id + ".");
        }

        byte[] encoded = null;

        // https://github.com/jwtk/jjwt/issues/478
        //
        // Some KeyStore implementations (like Hardware Security Modules and later versions of Android) will not allow
        // applications or libraries to obtain the secret key's encoded bytes.  In these cases, key length assertions
        // cannot be made, so we'll need to skip the key length checks if so.
        try {
            encoded = key.getEncoded();
        } catch (Exception ignored) {
        }

        // We can only perform length validation if key.getEncoded() is not null or does not throw an exception
        // per https://github.com/jwtk/jjwt/issues/478 and https://github.com/jwtk/jjwt/issues/619
        // so return early if we can't:
        if (encoded == null) return;

        int size = Arrays.length(encoded) * Byte.SIZE;
        if (size < this.minKeyLength) {
            String msg = "The " + keyType + " key's size is " + size + " bits which " +
                "is not secure enough for the " + id + " algorithm.";

            if (isJwaStandard() && isJwaStandardJcaName(getJcaName())) { //JWA standard algorithm name - reference the spec:
                msg += " The JWT " +
                    "JWA Specification (RFC 7518, Section 3.2) states that keys used with " + id + " MUST have a " +
                    "size >= " + minKeyLength + " bits (the key size must be greater than or equal to the hash " +
                    "output size). Consider using the SignatureAlgorithms." + id + ".generateKey() " +
                    "method to create a key guaranteed to be secure enough for " + id + ".  See " +
                    "https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
            } else { //custom algorithm - just indicate required key length:
                msg += " The " + id + " algorithm requires keys to have a size >= " + minKeyLength + " bits.";
            }

            throw new WeakKeyException(msg);
        }
    }

    @Override
    public byte[] doSign(final SignatureRequest<SecretKey> request) throws Exception {
        return execute(request, Mac.class, new InstanceCallback<Mac, byte[]>() {
            @Override
            public byte[] doWithInstance(Mac mac) throws Exception {
                mac.init(request.getKey());
                return mac.doFinal(request.getPayload());
            }
        });
    }
}
