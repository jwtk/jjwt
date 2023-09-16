/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.InvalidKeyException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * Derives a PublicKey from an Edwards-curve PrivateKey instance.
 */
final class EdwardsPublicKeyDeriver implements Function<PrivateKey, PublicKey> {

    public static final Function<PrivateKey, PublicKey> INSTANCE = new EdwardsPublicKeyDeriver();

    private EdwardsPublicKeyDeriver() {
        // prevent public instantiation.
    }

    @Override
    public PublicKey apply(PrivateKey privateKey) {

        EdwardsCurve curve = EdwardsCurve.findByKey(privateKey);
        if (curve == null) {
            String msg = "Unable to derive Edwards-curve PublicKey for specified PrivateKey: " + KeysBridge.toString(privateKey);
            throw new InvalidKeyException(msg);
        }

        byte[] pkBytes = curve.getKeyMaterial(privateKey);

        // This is a hack that utilizes the JCE implementations' behavior of using an RNG to generate a new private
        // key, and from that, the implementation computes a public key from the private key bytes.
        // Since we already have a private key, we provide a RNG that 'generates' the existing private key
        // instead of a random one, and the corresponding public key will be computed for us automatically.
        SecureRandom random = new ConstantRandom(pkBytes);
        KeyPair pair = curve.keyPair().random(random).build();
        Assert.stateNotNull(pair, "Edwards curve generated keypair cannot be null.");
        return Assert.stateNotNull(pair.getPublic(), "Edwards curve KeyPair must have a PublicKey");
    }

    private static final class ConstantRandom extends SecureRandom {
        private final byte[] value;

        public ConstantRandom(byte[] value) {
            this.value = value.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(value, 0, bytes, 0, value.length);
        }
    }
}
