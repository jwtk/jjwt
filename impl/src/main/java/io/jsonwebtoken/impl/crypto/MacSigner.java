/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.lang.Assert;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class MacSigner extends MacProvider implements Signer {

    public MacSigner(SignatureAlgorithm alg, byte[] key) {
        this(alg, new SecretKeySpec(key, alg.getJcaName()));
    }

    public MacSigner(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isHmac(), "The MacSigner only supports HMAC signature algorithms.");
        if (!(key instanceof SecretKey)) {
            String msg = "MAC signatures must be computed and verified using a SecretKey.  The specified key of " +
                         "type " + key.getClass().getName() + " is not a SecretKey.";
            throw new IllegalArgumentException(msg);
        }
    }

    @Override
    public byte[] sign(byte[] data) {
        Mac mac = getMacInstance();
        return mac.doFinal(data);
    }

    protected Mac getMacInstance() throws SignatureException {
        try {
            return doGetMacInstance();
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to obtain JCA MAC algorithm '" + alg.getJcaName() + "': " + e.getMessage();
            throw new SignatureException(msg, e);
        } catch (InvalidKeyException e) {
            String msg = "The specified signing key is not a valid " + alg.name() + " key: " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

    protected Mac doGetMacInstance() throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(alg.getJcaName());
        mac.init(key);
        return mac;
    }
}
