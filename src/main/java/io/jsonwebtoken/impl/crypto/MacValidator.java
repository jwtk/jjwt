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

import java.security.Key;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;

public class MacValidator implements SignatureValidator {

    private final Collection<MacSigner> signers;

    public MacValidator(SignatureAlgorithm alg, Collection<Key> keys) {
        Collection<MacSigner> signers = new ArrayList<MacSigner>();
        for (Key key: keys)
            signers.add(new MacSigner(alg, key));
        this.signers = signers;
    }

    @Override
    public boolean isValid(byte[] data, byte[] signature) {
        for (MacSigner signer: this.signers) {
            byte[] computed = signer.sign(data);
            if (MessageDigest.isEqual(computed, signature))
                return true;
        }
        return false;
    }
}
