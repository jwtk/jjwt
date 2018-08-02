package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SymmetricKeySignatureAlgorithm;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.LinkedHashSet;
import java.util.Set;

@SuppressWarnings("unused") //used via reflection in the io.jsonwebtoken.security.SignatureAlgorithms class
public class MacSignatureAlgorithm extends AbstractSignatureAlgorithm implements SymmetricKeySignatureAlgorithm {

    private final int minKeyLength; //in bits

    private static final Set<String> JWA_STANDARD_NAMES = new LinkedHashSet<>(Collections.of("HS256", "HS384", "HS512"));

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

    public MacSignatureAlgorithm(String name, String jcaName, int minKeyLength) {
        super(name, jcaName);
        Assert.isTrue(minKeyLength > 0, "minKeyLength must be greater than zero.");
        this.minKeyLength = minKeyLength;
    }

    int getMinKeyLength() {
        return this.minKeyLength;
    }

    private boolean isJwaStandard() {
        return JWA_STANDARD_NAMES.contains(getName());
    }

    private boolean isJwaStandardJcaName(String jcaName) {
        return VALID_HS256_JCA_NAMES.contains(jcaName.toUpperCase());
    }

    //For testing
    KeyGenerator doGetKeyGenerator(String jcaName) throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance(jcaName);
    }

    private KeyGenerator getKeyGenerator() {
        String jcaName = getJcaName();
        try {
            return doGetKeyGenerator(jcaName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "There is no JCA Provider available that supports the algorithm name '" + jcaName +
                "'.  Ensure this is a JCA standard name or you have registered a JCA security provider that " +
                "supports this name.";
            throw new UnsupportedOperationException(msg, e);
        }
    }

    @Override
    public SecretKey generateKey() {
        KeyGenerator generator = getKeyGenerator();
        generator.init(Randoms.secureRandom());
        return generator.generateKey();
    }

    //For testing
    Mac doGetMacInstance(String jcaName, Provider provider) throws NoSuchAlgorithmException {
        return provider == null ?
            Mac.getInstance(jcaName) :
            Mac.getInstance(jcaName, provider);
    }

    private Mac getMacInstance(CryptoRequest req) {
        Provider provider = req.getProvider();
        String jcaName = getJcaName();
        try {
            return doGetMacInstance(jcaName, provider);
        } catch (NoSuchAlgorithmException e) {
            String msg;
            if (provider != null) {
                msg = "The specified JCA Provider {" + provider + "} does not support ";
            } else {
                msg = "There is no JCA Provider available that supports ";
            }
            msg += "MAC algorithm name '" + jcaName + "'.";
            throw new SignatureException(msg, e);
        }
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

        final String name = getName();

        String alg = key.getAlgorithm();
        if (!Strings.hasText(alg)) {
            String msg = "The " + keyType + " key's algorithm cannot be null or empty.";
            throw new InvalidKeyException(msg);
        }

        //assert key's jca name is valid if it's a JWA standard algorithm:
        if (isJwaStandard() && !isJwaStandardJcaName(alg)) {
            throw new InvalidKeyException("The " + keyType + " key's algorithm '" + alg + "' does not equal a valid " +
                "HmacSHA* algorithm name or PKCS12 OID and cannot be used with " + name + ".");
        }

        byte[] encoded = null;

        // https://github.com/jwtk/jjwt/issues/478
        //
        // Some HSM modules will not allow applications or libraries to obtain the secret key's encoded bytes.  In
        // these cases, key length assertions cannot be made, so we'll need to skip the key length checks if so.
        try {
            encoded = key.getEncoded();
        } catch (Exception ignored) {
        }

        if (encoded != null) { //we can perform key length assertions
            int size = Arrays.length(encoded) * Byte.SIZE;
            if (size < this.minKeyLength) {
                String msg = "The " + keyType + " key's size is " + size + " bits which " +
                    "is not secure enough for the " + name + " algorithm.";

                if (isJwaStandard() && isJwaStandardJcaName(getJcaName())) { //JWA standard algorithm name - reference the spec:
                    msg += " The JWT " +
                        "JWA Specification (RFC 7518, Section 3.2) states that keys used with " + name + " MUST have a " +
                        "size >= " + minKeyLength + " bits (the key size must be greater than or equal to the hash " +
                        "output size). Consider using the SignatureAlgorithms." + name + ".generateKey() " +
                        "method to create a key guaranteed to be secure enough for " + name + ".  See " +
                        "https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
                } else { //custom algorithm - just indicate required key length:
                    msg += " The " + name + " algorithm requires keys to have a size >= " + minKeyLength + " bits.";
                }

                throw new WeakKeyException(msg);
            }
        }
    }

    @Override
    public byte[] doSign(CryptoRequest<byte[], Key> request) throws Exception {
        Key key = request.getKey();
        Mac mac = getMacInstance(request);
        mac.init(key);
        return mac.doFinal(request.getData());
    }
}
