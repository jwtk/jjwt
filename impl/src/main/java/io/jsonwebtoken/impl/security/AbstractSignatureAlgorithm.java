/*
 * Copyright © 2018 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.text.MessageFormat;

abstract class AbstractSignatureAlgorithm extends AbstractSecureDigestAlgorithm<PrivateKey, PublicKey>
        implements SignatureAlgorithm {

    private static final String KEY_TYPE_MSG_PATTERN =
            "{0} {1} keys must be {2}s (implement {3}). Provided key type: {4}.";

    AbstractSignatureAlgorithm(String id, String jcaName) {
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

    protected final byte[] sign(Signature sig, InputStream payload) throws Exception {
        byte[] buf = new byte[2048];
        int len = 0;
        while (len != -1) {
            len = payload.read(buf);
            if (len > 0) sig.update(buf, 0, len);
        }
        return sig.sign();
    }

    @Override
    protected byte[] doDigest(final SecureRequest<InputStream, PrivateKey> request) {
        return jca(request).withSignature(new CheckedFunction<Signature, byte[]>() {
            @Override
            public byte[] apply(Signature sig) throws Exception {
                sig.initSign(request.getKey());
                return sign(sig, request.getPayload());
            }
        });
    }

    protected boolean verify(Signature sig, InputStream payload, byte[] digest) throws Exception {
        byte[] buf = new byte[1024];
        int len = 0;
        while (len != -1) {
            len = payload.read(buf);
            if (len > 0) sig.update(buf, 0, len);
        }
        return sig.verify(digest);
    }

    @Override
    protected boolean doVerify(final VerifySecureDigestRequest<PublicKey> request) {
        return jca(request).withSignature(new CheckedFunction<Signature, Boolean>() {
            @Override
            public Boolean apply(Signature sig) throws Exception {
                sig.initVerify(request.getKey());
                return verify(sig, request.getPayload(), request.getDigest());
            }
        });
    }
}
