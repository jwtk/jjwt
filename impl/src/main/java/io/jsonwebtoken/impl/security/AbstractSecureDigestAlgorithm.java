/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.security.Key;

abstract class AbstractSecureDigestAlgorithm<S extends Key, V extends Key> extends CryptoAlgorithm implements SecureDigestAlgorithm<S, V> {

    AbstractSecureDigestAlgorithm(String id, String jcaName) {
        super(id, jcaName);
    }

    protected static String keyType(boolean signing) {
        return signing ? "signing" : "verification";
    }

    protected abstract void validateKey(Key key, boolean signing);

    @Override
    public final byte[] digest(SecureRequest<byte[], S> request) throws SecurityException {
        Assert.notNull(request, "Request cannot be null.");
        final S key = Assert.notNull(request.getKey(), "Signing key cannot be null.");
        Assert.notEmpty(request.getPayload(), "Request content cannot be null or empty.");
        try {
            validateKey(key, true);
            return doDigest(request);
        } catch (SignatureException | KeyException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to compute " + getId() + " signature with JCA algorithm '" + getJcaName() + "' " +
                    "using key {" + KeysBridge.toString(key) + "}: " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected abstract byte[] doDigest(SecureRequest<byte[], S> request) throws Exception;

    @Override
    public final boolean verify(VerifySecureDigestRequest<V> request) throws SecurityException {
        Assert.notNull(request, "Request cannot be null.");
        final V key = Assert.notNull(request.getKey(), "Verification key cannot be null.");
        Assert.notEmpty(request.getPayload(), "Request content cannot be null or empty.");
        Assert.notEmpty(request.getDigest(), "Request signature byte array cannot be null or empty.");
        try {
            validateKey(key, false);
            return doVerify(request);
        } catch (SignatureException | KeyException e) {
            throw e; //propagate
        } catch (Exception e) {
            String msg = "Unable to verify " + getId() + " signature with JCA algorithm '" + getJcaName() + "' " +
                    "using key {" + KeysBridge.toString(key) + "}: " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected abstract boolean doVerify(VerifySecureDigestRequest<V> request);
}
