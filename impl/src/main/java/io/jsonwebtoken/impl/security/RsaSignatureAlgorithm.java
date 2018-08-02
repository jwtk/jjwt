package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.AsymmetricKeySignatureAlgorithm;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.VerifySignatureRequest;
import io.jsonwebtoken.security.WeakKeyException;

import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

@SuppressWarnings("unused") //used via reflection in the io.jsonwebtoken.security.SignatureAlgorithms class
public class RsaSignatureAlgorithm extends AbstractSignatureAlgorithm implements AsymmetricKeySignatureAlgorithm {

    static {
        RuntimeEnvironment.enableBouncyCastleIfPossible(); //PS256, PS384, PS512 on <= JDK 10 require BC
    }

    private static final int MIN_KEY_LENGTH_BITS = 2048;

    private static AlgorithmParameterSpec pssParamFromSaltBitLength(int saltBitLength) {
        MGF1ParameterSpec ps = new MGF1ParameterSpec("SHA-" + saltBitLength);
        //MGF1ParameterSpec ps = MGF1ParameterSpec.SHA256;
        int saltByteLength = saltBitLength / Byte.SIZE;
        return new PSSParameterSpec(ps.getDigestAlgorithm(), "MGF1", ps, saltByteLength, 1);
    }

    private final int preferredKeyLength;

    private final AlgorithmParameterSpec algorithmParameterSpec;

    public RsaSignatureAlgorithm(String name, String jcaName, int preferredKeyLengthBits, AlgorithmParameterSpec algParam) {
        super(name, jcaName);
        if (preferredKeyLengthBits < MIN_KEY_LENGTH_BITS) {
            String msg = "preferredKeyLengthBits must be greater than the JWA mandatory minimum key length of " + MIN_KEY_LENGTH_BITS;
            throw new IllegalArgumentException(msg);
        }
        this.preferredKeyLength = preferredKeyLengthBits;
        this.algorithmParameterSpec = algParam;
    }

    public RsaSignatureAlgorithm(String name, String jcaName, int preferredKeyLengthBits) {
        this(name, jcaName, preferredKeyLengthBits, null);
    }

    public RsaSignatureAlgorithm(String name, String jcaName, int preferredKeyLengthBits, int pssSaltLengthBits) {
        this(name, jcaName, preferredKeyLengthBits, pssParamFromSaltBitLength(pssSaltLengthBits));
    }

    //for testing visibility
    protected KeyPairGenerator getKeyPairGenerator() throws NoSuchAlgorithmException, InvalidParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(preferredKeyLength, Randoms.secureRandom());
        return generator;
    }

    @Override
    public KeyPair generateKeyPair() {
        KeyPairGenerator generator;
        try {
            generator = getKeyPairGenerator();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to obtain an RSA KeyPairGenerator: " + e.getMessage(), e);
        }
        return generator.genKeyPair();
    }

    @Override
    protected void validateKey(Key key, boolean signing) {

        if (!(key instanceof RSAKey)) {
            String msg = "RSA " + keyType(signing) + " keys must be an RSAKey.  The specified key is of type: " +
                key.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        // https://github.com/jwtk/jjwt/issues/68
        // Instead of checking for an instance of RSAPrivateKey, check for PrivateKey (RSAKey assertion is above):
        if (signing && !(key instanceof PrivateKey)) {
            String msg = "Asymmetric key signatures must be created with PrivateKeys. The specified key is of type: " +
                key.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        RSAKey rsaKey = (RSAKey) key;
        int size = rsaKey.getModulus().bitLength();
        if (size < MIN_KEY_LENGTH_BITS) {

            String name = getName();

            String section = name.startsWith("PS") ? "3.5" : "3.3";

            String msg = "The " + keyType(signing) + " key's size is " + size + " bits which is not secure " +
                "enough for the " + name + " algorithm.  The JWT JWA Specification (RFC 7518, Section " +
                section + ") states that RSA keys MUST have a size >= " +
                MIN_KEY_LENGTH_BITS + " bits.  Consider using the SignatureAlgorithms." + name + ".generateKeyPair() " +
                "method to create a key pair guaranteed to be secure enough for " + name + ".  See " +
                "https://tools.ietf.org/html/rfc7518#section-" + section + " for more information.";
            throw new WeakKeyException(msg);
        }
    }

    @Override
    protected byte[] doSign(CryptoRequest<byte[], Key> request) throws Exception {
        PrivateKey privateKey = (PrivateKey) request.getKey();
        Signature sig = createSignatureInstance(request.getProvider(), this.algorithmParameterSpec);
        sig.initSign(privateKey);
        sig.update(request.getData());
        return sig.sign();
    }

    @Override
    protected boolean doVerify(VerifySignatureRequest request) throws Exception {
        final Key key = request.getKey();
        if (key instanceof PrivateKey) {
            return super.doVerify(request);
        }

        PublicKey publicKey = (PublicKey) key;
        Signature sig = createSignatureInstance(request.getProvider(), this.algorithmParameterSpec);
        sig.initVerify(publicKey);
        sig.update(request.getData());
        return sig.verify(request.getSignature());
    }
}
