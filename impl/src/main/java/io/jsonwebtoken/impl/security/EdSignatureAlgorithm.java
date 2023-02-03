package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.VerifyDigestRequest;

import java.security.Key;

public class EdSignatureAlgorithm extends AbstractSignatureAlgorithm {

    private static final String ID = "EdDSA";

    private final EdwardsCurve preferredCurve;

    public EdSignatureAlgorithm() {
        super(ID, ID);
        this.preferredCurve = EdwardsCurve.Ed448;
        // EdDSA is not available natively until JDK 15, so try to load BC as a backup provider if possible:
        setProvider(this.preferredCurve.getProvider());
    }

    public EdSignatureAlgorithm(EdwardsCurve preferredCurve) {
        super(ID, preferredCurve.getJcaName());
        this.preferredCurve = Assert.notNull(preferredCurve, "preferredCurve cannot be null.");
        Assert.isTrue(preferredCurve.isSignatureCurve(), "EdwardsCurve must be a signature curve, not a key agreement curve.");
        setProvider(preferredCurve.getProvider());
    }

    @Override
    protected String getJcaName(Request<?> request) {
        SecureRequest<?, ?> req = Assert.isInstanceOf(SecureRequest.class, request, "SecureRequests are required.");
        Key key = req.getKey();

        // If we're signing, and this instance's algorithm name is the default/generic 'EdDSA', then prefer the
        // signing key's curve algorithm ID.  This ensures the most specific JCA algorithm is used for signing,
        // (while generic 'EdDSA' is fine for validation)
        String jcaName = getJcaName(); //default for JCA interaction
        boolean signing = !(request instanceof VerifyDigestRequest);
        if (ID.equals(jcaName) && signing) { // see if we can get a more-specific curve algorithm identifier:
            EdwardsCurve curve = EdwardsCurve.findByKey(key);
            if (curve != null) {
                jcaName = curve.getJcaName(); // prefer the key's specific curve algorithm identifier during signing
            }
        }
        return jcaName;
    }

    @Override
    public KeyPairBuilder keyPairBuilder() {
        return this.preferredCurve.keyPairBuilder();
    }

    @Override
    protected void validateKey(Key key, boolean signing) {
        super.validateKey(key, signing);
        EdwardsCurve curve = EdwardsCurve.findByKey(key);
        if (curve != null && !curve.isSignatureCurve()) {
            String msg = curve.getId() + " keys may not be used with " + getId() + " digital signatures per " +
                    "https://www.rfc-editor.org/rfc/rfc8037#section-3.2";
            throw new InvalidKeyException(msg);
        }
    }
}
