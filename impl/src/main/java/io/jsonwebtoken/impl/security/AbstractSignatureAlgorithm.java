package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.text.MessageFormat;

abstract class AbstractSignatureAlgorithm extends AbstractSecureDigestAlgorithm<PrivateKey, PublicKey>
        implements SignatureAlgorithm {

    private static final String KEY_TYPE_MSG_PATTERN =
            "{0} {1} keys must be {2}s (implement {3}). Provided key type: {4}.";

    protected AbstractSignatureAlgorithm(String id, String jcaName) {
        super(id, jcaName);
    }

    @Override
    protected void validateKey(Key key, boolean signing) {
        // https://github.com/jwtk/jjwt/issues/68:
        Class<?> type = signing ? PrivateKey.class : PublicKey.class;
        if (!type.isInstance(key)) {
            String msg = MessageFormat.format(KEY_TYPE_MSG_PATTERN, getId(),
                    keyType(signing), type.getSimpleName(), type.getName(), key.getClass().getName());
            throw new InvalidKeyException(msg);
        }
    }

    @Override
    protected byte[] doDigest(final SecureRequest<byte[], PrivateKey> request) {
        return jca(request).withSignature(new CheckedFunction<Signature, byte[]>() {
            @Override
            public byte[] apply(Signature sig) throws Exception {
                sig.initSign(request.getKey());
                sig.update(request.getPayload());
                return sig.sign();
            }
        });
    }

    @Override
    protected boolean doVerify(final VerifySecureDigestRequest<PublicKey> request) {
        return jca(request).withSignature(new CheckedFunction<Signature, Boolean>() {
            @Override
            public Boolean apply(Signature sig) throws Exception {
                sig.initVerify(request.getKey());
                sig.update(request.getPayload());
                return sig.verify(request.getDigest());
            }
        });
    }
}
