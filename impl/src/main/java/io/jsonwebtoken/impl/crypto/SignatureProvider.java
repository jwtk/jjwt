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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.RuntimeEnvironment;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;

abstract class SignatureProvider {

    /**
     * JJWT's default SecureRandom number generator.  This RNG is initialized using the JVM default as follows:
     *
     * <pre><code>
     * static {
     *     DEFAULT_SECURE_RANDOM = new SecureRandom();
     *     DEFAULT_SECURE_RANDOM.nextBytes(new byte[64]);
     * }
     * </code></pre>
     *
     * <p><code>nextBytes</code> is called to force the RNG to initialize itself if not already initialized.  The
     * byte array is not used and discarded immediately for garbage collection.</p>
     */
    public static final SecureRandom DEFAULT_SECURE_RANDOM;

    static {
        DEFAULT_SECURE_RANDOM = new SecureRandom();
        DEFAULT_SECURE_RANDOM.nextBytes(new byte[64]);
    }

    protected final SignatureAlgorithm alg;
    protected final Key key;

    protected SignatureProvider(SignatureAlgorithm alg, Key key) {
        Assert.notNull(alg, "SignatureAlgorithm cannot be null.");
        Assert.notNull(key, "Key cannot be null.");
        this.alg = alg;
        this.key = key;
    }

    protected Signature createSignatureInstance() {
        try {
            return getSignatureInstance();
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unavailable " + alg.getFamilyName() + " Signature algorithm '" + alg.getJcaName() + "'.";
            if (!alg.isJdkStandard() && !isBouncyCastleAvailable()) {
                msg += " This is not a standard JDK algorithm. Try including BouncyCastle in the runtime classpath.";
            }
            throw new SignatureException(msg, e);
        }
    }

    protected Signature getSignatureInstance() throws NoSuchAlgorithmException {
        return Signature.getInstance(alg.getJcaName());
    }

    protected boolean isBouncyCastleAvailable() {
        return RuntimeEnvironment.BOUNCY_CASTLE_AVAILABLE;
    }
}
