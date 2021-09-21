package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.RsaSignatureAlgorithm;
import io.jsonwebtoken.security.SignatureRequest;
import io.jsonwebtoken.security.VerifySignatureRequest;
import io.jsonwebtoken.security.WeakKeyException;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class DefaultRsaSignatureAlgorithm<SK extends RSAKey & PrivateKey, VK extends RSAKey & PublicKey> extends AbstractSignatureAlgorithm<SK, VK> implements RsaSignatureAlgorithm<SK, VK> {

    static {
        RuntimeEnvironment.enableBouncyCastleIfPossible(); //PS256, PS384, PS512 on <= JDK 10 require BC
    }

    private static final int MIN_KEY_LENGTH_BITS = 2048;

    private static AlgorithmParameterSpec pssParamFromSaltBitLength(int saltBitLength) {
        MGF1ParameterSpec ps = new MGF1ParameterSpec("SHA-" + saltBitLength);
        int saltByteLength = saltBitLength / Byte.SIZE;
        return new PSSParameterSpec(ps.getDigestAlgorithm(), "MGF1", ps, saltByteLength, 1);
    }

    private final int preferredKeyLength;

    private final AlgorithmParameterSpec algorithmParameterSpec;

    public DefaultRsaSignatureAlgorithm(String name, String jcaName, int preferredKeyLengthBits, AlgorithmParameterSpec algParam) {
        super(name, jcaName);
        if (preferredKeyLengthBits < MIN_KEY_LENGTH_BITS) {
            String msg = "preferredKeyLengthBits must be greater than the JWA mandatory minimum key length of " + MIN_KEY_LENGTH_BITS;
            throw new IllegalArgumentException(msg);
        }
        this.preferredKeyLength = preferredKeyLengthBits;
        this.algorithmParameterSpec = algParam;
    }

    public DefaultRsaSignatureAlgorithm(int digestBitLength, int preferredKeyBitLength) {
        this("RS" + digestBitLength, "SHA" + digestBitLength + "withRSA", preferredKeyBitLength);
    }

    public DefaultRsaSignatureAlgorithm(int digestBitLength, int preferredKeyBitLength, int pssSaltBitLength) {
        this("PS" + digestBitLength, "RSASSA-PSS", preferredKeyBitLength, pssSaltBitLength);
    }

    public DefaultRsaSignatureAlgorithm(String name, String jcaName, int preferredKeyLengthBits) {
        this(name, jcaName, preferredKeyLengthBits, null);
    }

    public DefaultRsaSignatureAlgorithm(String name, String jcaName, int preferredKeyLengthBits, int pssSaltLengthBits) {
        this(name, jcaName, preferredKeyLengthBits, pssParamFromSaltBitLength(pssSaltLengthBits));
    }

    @Override
    public KeyPair generateKeyPair() {
        return new JcaTemplate("RSA", null).generateKeyPair(this.preferredKeyLength);
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

            String id = getId();

            String section = id.startsWith("PS") ? "3.5" : "3.3";

            String msg = "The " + keyType(signing) + " key's size is " + size + " bits which is not secure " +
                "enough for the " + id + " algorithm.  The JWT JWA Specification (RFC 7518, Section " +
                section + ") states that RSA keys MUST have a size >= " +
                MIN_KEY_LENGTH_BITS + " bits.  Consider using the SignatureAlgorithms." + id + ".generateKeyPair() " +
                "method to create a key pair guaranteed to be secure enough for " + id + ".  See " +
                "https://tools.ietf.org/html/rfc7518#section-" + section + " for more information.";
            throw new WeakKeyException(msg);
        }
    }

    @Override
    protected byte[] doSign(final SignatureRequest<SK> request) throws Exception {
        return execute(request, Signature.class, new InstanceCallback<Signature, byte[]>() {
            @Override
            public byte[] doWithInstance(Signature sig) throws Exception {
                if (algorithmParameterSpec != null) {
                    sig.setParameter(algorithmParameterSpec);
                }
                sig.initSign(request.getKey());
                sig.update(request.getPayload());
                return sig.sign();
            }
        });
    }

    @Override
    protected boolean doVerify(final VerifySignatureRequest<VK> request) throws Exception {
        final Key key = request.getKey();
        if (key instanceof PrivateKey) { //legacy support only
            return super.doVerify(request);
        }
        return execute(request, Signature.class, new InstanceCallback<Signature, Boolean>() {
            @Override
            public Boolean doWithInstance(Signature sig) throws Exception {
                if (algorithmParameterSpec != null) {
                    sig.setParameter(algorithmParameterSpec);
                }
                sig.initVerify(request.getKey());
                sig.update(request.getPayload());
                return sig.verify(request.getSignature());
            }
        });
    }
}
