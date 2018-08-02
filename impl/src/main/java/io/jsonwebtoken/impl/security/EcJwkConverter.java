package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.PublicEcJwkBuilder;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

public class EcJwkConverter extends AbstractTypedJwkConverter {

    private static final Map<String,String> EC_CURVE_NAMES_BY_JWA_ID = createEcCurveNameMap();

    private static Map<String, String> createEcCurveNameMap() {
        Map<String,String> m = new HashMap<>();
        m.put("P-256", "secp256r1");
        m.put("P-384", "secp384r1");
        m.put("P-521", "secp521r1");
        return m;
    }

    private static ECParameterSpec getStandardNameSpec(String stdName) throws KeyException {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(stdName));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            String msg = "Unable to obtain JVM ECParameterSpec for JWA curve ID '" + stdName + "'.";
            throw new KeyException(msg, e);
        }
    }

    private static ECParameterSpec getCurveIdSpec(String curveId) {
        String stdName = EC_CURVE_NAMES_BY_JWA_ID.get(curveId);
        if (stdName == null) {
            String msg = "Unrecognized JWA curve id '" + curveId + "'";
            throw new UnsupportedKeyException(msg);
        }
        return getStandardNameSpec(stdName);
    }

    /**
     * https://tools.ietf.org/html/rfc7518#section-6.2.1.2 indicates that this algorithm logic is defined in
     * http://www.secg.org/sec1-v2.pdf Section 2.3.5.
     * @param fieldSize EC field size
     * @param coordinate EC point coordinate (e.g. x or y)
     * @return A base64Url-encoded String representing the EC field per the RFC format
     */
    // Algorithm defined in http://www.secg.org/sec1-v2.pdf Section 2.3.5
    static String encodeCoordinate(int fieldSize, BigInteger coordinate) {
        byte[] bytes = toUnsignedBytes(coordinate);
        int mlen = (int)Math.ceil(fieldSize / 8d);
        if (mlen > bytes.length) {
            byte[] m = new byte[mlen];
            System.arraycopy(bytes, 0, m, mlen - bytes.length, bytes.length);
            bytes = m;
        }
        return Encoders.BASE64URL.encode(bytes);
    }

    EcJwkConverter() {
        super("EC");
    }

    @Override
    public boolean supports(Key key) {
        return key instanceof ECPrivateKey || key instanceof ECPublicKey;
    }

    @Override
    public Key toKey(Map<String, ?> jwk) {
        Assert.notNull(jwk, "JWK map argument cannot be null.");
        if (jwk.containsKey("d")) {
            return toPrivateKey(jwk);
        }
        return toPublicKey(jwk);
    }

    @Override
    public Map<String, String> toJwk(Key key) {
        if (key instanceof ECPrivateKey) {
            return toPrivateJwk((ECPrivateKey)key);
        }
        Assert.isInstanceOf(ECPublicKey.class, key, "Key argument must be an ECPublicKey or ECPrivateKey instance.");
        return toPublicJwk((ECPublicKey)key);
    }

    private ECPublicKey toPublicKey(Map<String, ?> jwk) {
        String curveId = getRequiredString(jwk, "crv");
        BigInteger x = getRequiredBigInt(jwk, "x");
        BigInteger y = getRequiredBigInt(jwk, "y");

        ECParameterSpec spec = getCurveIdSpec(curveId);
        ECPoint point = new ECPoint(x, y);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);

        try {
            KeyFactory kf = getKeyFactory();
            return (ECPublicKey)kf.generatePublic(pubSpec);
        } catch (Exception e) {
            String msg = "Unable to obtain ECPublicKey for curve '" + curveId + "'.";
            throw new KeyException(msg, e);
        }
    }

    public ECPrivateKey toPrivateKey(Map<String,?> jwk) {
        String curveId = getRequiredString(jwk, "crv");
        BigInteger d = getRequiredBigInt(jwk, "d");

        // We don't actually need these two values for JVM lookup, but the
        // [JWA spec](https://tools.ietf.org/html/rfc7518#section-6.2.2)
        // requires them to be present and valid for the private key as well, so we assert that here:
        getRequiredBigInt(jwk, "x");
        getRequiredBigInt(jwk, "y");

        ECParameterSpec spec = getCurveIdSpec(curveId);
        ECPrivateKeySpec privateSpec = new ECPrivateKeySpec(d, spec);

        try {
            KeyFactory kf = getKeyFactory();
            return (ECPrivateKey)kf.generatePrivate(privateSpec);
        } catch (Exception e) {
            String msg = "Unable to obtain ECPrivateKey from specified jwk for curve '" + curveId + "'.";
            throw new KeyException(msg, e);
        }
    }

    public Map<String, String> toPublicJwk(ECPublicKey key) {

        PublicEcJwkBuilder builder = Jwks.builder().ellipticCurve().publicKey();

        Map<String,String> m = newJwkMap();

        System.out.println(key.getAlgorithm());

        ECParameterSpec spec = key.getParams();

        //TODO: need a ECPublicKey-to-CurveId function

        SignatureAlgorithm alg = SignatureAlgorithm.forSigningKey(key);

        int bitLength = spec.getOrder().bitLength();

        int fieldSize = spec.getCurve().getField().getFieldSize();

        String x = encodeCoordinate(fieldSize, spec.getGenerator().getAffineX());
        String y = encodeCoordinate(fieldSize, spec.getGenerator().getAffineY());


        builder.setX(x).setY(y);

        //return (Map<String,String>)builder.build();

        throw new UnsupportedOperationException("Not yet implemented.");
    }



    public Map<String, String> toPrivateJwk(ECPrivateKey key) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
