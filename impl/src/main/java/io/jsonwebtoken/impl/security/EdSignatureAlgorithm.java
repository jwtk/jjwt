package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecureRequest;

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
        setProvider(preferredCurve.getProvider());
    }

    @Override
    protected String getJcaName(Request<?> request) {
        SecureRequest<?, ?> req = Assert.isInstanceOf(SecureRequest.class, request,
                "Only SecureRequests are supported.");
        Key key = req.getKey();
        EdwardsCurve curve = EdwardsCurve.findByKey(key);
        if (curve != null) {
            return curve.getJcaName(); // prefer the key's specific curve algorithm identifier
        }
        //otherwise we'll fall back to the generic 'EdDSA' algorithm name for JCA interaction
        return super.getJcaName(request);
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
