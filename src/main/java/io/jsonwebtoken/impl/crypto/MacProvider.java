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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

public abstract class MacProvider extends SignatureProvider {

    protected MacProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isHmac(), "SignatureAlgorithm must be a HMAC SHA algorithm.");
    }

    /**
     * Generates a new secure-random 512 bit secret key suitable for creating and verifying HMAC signatures.  This is a
     * convenience method that immediately delegates to {@link #generateKey(SignatureAlgorithm)} using {@link
     * SignatureAlgorithm#HS512} as the method argument.
     *
     * @return a new secure-random 512 bit secret key suitable for creating and verifying HMAC signatures.
     * @see #generateKey(SignatureAlgorithm)
     * @see #generateKey(SignatureAlgorithm, SecureRandom)
     * @since 0.5
     */
    public static SecretKey generateKey() {
        return generateKey(SignatureAlgorithm.HS512);
    }

    /**
     * Generates a new secure-random secret key of a length suitable for creating and verifying HMAC signatures
     * according to the specified {@code SignatureAlgorithm} using JJWT's default {@link
     * SignatureProvider#DEFAULT_SECURE_RANDOM SecureRandom instance}.  This is a convenience method that immediately
     * delegates to {@link #generateKey(SignatureAlgorithm, SecureRandom)}.
     *
     * @param alg the desired signature algorithm
     * @return a new secure-random secret key of a length suitable for creating and verifying HMAC signatures according
     * to the specified {@code SignatureAlgorithm} using JJWT's default {@link SignatureProvider#DEFAULT_SECURE_RANDOM
     * SecureRandom instance}.
     * @see #generateKey()
     * @see #generateKey(SignatureAlgorithm, SecureRandom)
     * @since 0.5
     */
    public static SecretKey generateKey(SignatureAlgorithm alg) {
        return generateKey(alg, SignatureProvider.DEFAULT_SECURE_RANDOM);
    }

    /**
     * Generates a new secure-random secret key of a length suitable for creating and verifying HMAC signatures
     * according to the specified {@code SignatureAlgorithm} using the specified SecureRandom number generator.  This
     * implementation returns secure-random key sizes as follows:
     *
     * <table> <caption>Key Sizes</caption> <thead> <tr> <th>Signature Algorithm</th> <th>Generated Key Size</th> </tr> </thead> <tbody> <tr>
     * <td>HS256</td> <td>256 bits (32 bytes)</td> </tr> <tr> <td>HS384</td> <td>384 bits (48 bytes)</td> </tr> <tr>
     * <td>HS512</td> <td>512 bits (64 bytes)</td> </tr> </tbody> </table>
     *
     * @param alg    the signature algorithm that will be used with the generated key
     * @param random the secure random number generator used during key generation
     * @return a new secure-random secret key of a length suitable for creating and verifying HMAC signatures according
     * to the specified {@code SignatureAlgorithm} using the specified SecureRandom number generator.
     * @see #generateKey()
     * @see #generateKey(SignatureAlgorithm)
     * @since 0.5
     */
    public static SecretKey generateKey(SignatureAlgorithm alg, SecureRandom random) {

        Assert.isTrue(alg.isHmac(), "SignatureAlgorithm argument must represent an HMAC algorithm.");

        byte[] bytes;

        switch (alg) {
            case HS256:
                bytes = new byte[32];
                break;
            case HS384:
                bytes = new byte[48];
                break;
            default:
                bytes = new byte[64];
        }

        random.nextBytes(bytes);

        return new SecretKeySpec(bytes, alg.getJcaName());
    }
}
