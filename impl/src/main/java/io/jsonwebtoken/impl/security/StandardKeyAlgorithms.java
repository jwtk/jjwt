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

import io.jsonwebtoken.impl.lang.DelegatingRegistry;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.KeyAlgorithm;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

/**
 * Static class definitions for standard {@link KeyAlgorithm} instances.
 *
 * @since JJWT_RELEASE_VERSION
 */
public final class StandardKeyAlgorithms extends DelegatingRegistry<String, KeyAlgorithm<?, ?>> {

    private static final String RSA1_5_ID = "RSA1_5";
    private static final String RSA1_5_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String RSA_OAEP_ID = "RSA-OAEP";
    private static final String RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String RSA_OAEP_256_ID = "RSA-OAEP-256";
    private static final String RSA_OAEP_256_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final AlgorithmParameterSpec RSA_OAEP_256_SPEC =
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    public StandardKeyAlgorithms() {
        super(new IdRegistry<>("JWE Key Management Algorithm", Collections.<KeyAlgorithm<?, ?>>of(
                new DirectKeyAlgorithm(),
                new AesWrapKeyAlgorithm(128),
                new AesWrapKeyAlgorithm(192),
                new AesWrapKeyAlgorithm(256),
                new AesGcmKeyAlgorithm(128),
                new AesGcmKeyAlgorithm(192),
                new AesGcmKeyAlgorithm(256),
                new Pbes2HsAkwAlgorithm(128),
                new Pbes2HsAkwAlgorithm(192),
                new Pbes2HsAkwAlgorithm(256),
                new EcdhKeyAlgorithm(),
                new EcdhKeyAlgorithm(new AesWrapKeyAlgorithm(128)),
                new EcdhKeyAlgorithm(new AesWrapKeyAlgorithm(192)),
                new EcdhKeyAlgorithm(new AesWrapKeyAlgorithm(256)),
                new DefaultRsaKeyAlgorithm(RSA1_5_ID, RSA1_5_TRANSFORMATION),
                new DefaultRsaKeyAlgorithm(RSA_OAEP_ID, RSA_OAEP_TRANSFORMATION),
                new DefaultRsaKeyAlgorithm(RSA_OAEP_256_ID, RSA_OAEP_256_TRANSFORMATION, RSA_OAEP_256_SPEC)
        ), false));
    }

    /*
    private static KeyAlgorithm<Password, Password> lean(final Pbes2HsAkwAlgorithm alg) {

        // ensure we use the same key factory over and over so that time spent acquiring one is not repeated:
        JcaTemplate template = new JcaTemplate(alg.getJcaName(), null, Randoms.secureRandom());
        final SecretKeyFactory factory = template.execute(SecretKeyFactory.class, new CheckedFunction<SecretKeyFactory, SecretKeyFactory>() {
            @Override
            public SecretKeyFactory apply(SecretKeyFactory secretKeyFactory) {
                return secretKeyFactory;
            }
        });

        // pre-compute the salt so we don't spend time doing that on each iteration.  Doesn't need to be random for a
        // computation-only test:
        final byte[] rfcSalt = alg.toRfcSalt(alg.generateInputSalt(null));

        // ensure that the bare minimum steps are performed to hash, ensuring our time sampling pertains only to
        // hashing and not ancillary steps needed to setup the hashing/derivation
        return new KeyAlgorithm<Password, Password>() {
            @Override
            public KeyResult getEncryptionKey(KeyRequest<Password> request) throws SecurityException {
                int iterations = request.getHeader().getPbes2Count();
                char[] password = request.getKey().getPassword();
                try {
                    alg.deriveKey(factory, password, rfcSalt, iterations);
                } catch (Exception e) {
                    throw new SecurityException("Unable to derive key", e);
                }
                return null;
            }

            @Override
            public SecretKey getDecryptionKey(DecryptionKeyRequest<Password> request) throws SecurityException {
                throw new UnsupportedOperationException("Not intended to be called.");
            }

            @Override
            public String getId() {
                return alg.getId();
            }
        };
    }

    private static char randomChar() {
        return (char) Randoms.secureRandom().nextInt(Character.MAX_VALUE);
    }

    private static char[] randomChars(@SuppressWarnings("SameParameterValue") int length) {
        char[] chars = new char[length];
        for (int i = 0; i < length; i++) {
            chars[i] = randomChar();
        }
        return chars;
    }

    public static int estimateIterations(KeyAlgorithm<Password, Password> alg, long desiredMillis) {

        // The number of computational samples that land in our 'sweet spot' timing range matching desiredMillis.
        // These samples will be averaged and the final average will be the return value of this method
        // representing the number of iterations that should be taken for any given PBE hashing attempt to get
        // reasonably close to desiredMillis:
        final int NUM_SAMPLES = 30;
        final int SKIP = 3;
        // More important than the actual password (or characters) is the password length.
        // 8 characters is a commonly-found minimum required length in many systems circa 2021.
        final int PASSWORD_LENGTH = 8;

        final JweHeader HEADER = new DefaultJweHeader();
        final AeadAlgorithm ENC_ALG = Jwts.ENC.A128GCM; // not used, needed to satisfy API

        if (alg instanceof Pbes2HsAkwAlgorithm) {
            // Strip away all things that cause time during computation except for the actual hashing algorithm:
            alg = lean((Pbes2HsAkwAlgorithm) alg);
        }

        int workFactor = 1000; // same as iterations for PBKDF2.  Different concept for Bcrypt/Scrypt
        int minWorkFactor = workFactor;
        List<Point> points = new ArrayList<>(NUM_SAMPLES);
        for (int i = 0; points.size() < NUM_SAMPLES; i++) {

            char[] password = randomChars(PASSWORD_LENGTH);
            Password key = Keys.password(password);
            HEADER.pbes2Count(workFactor);
            KeyRequest<Password> request = new DefaultKeyRequest<>(null, null, key, HEADER, ENC_ALG);

            long start = System.currentTimeMillis();
            alg.getEncryptionKey(request); // <-- Computation occurs here.  Don't need the result, just need to exec
            long end = System.currentTimeMillis();
            long duration = end - start;

            // Exclude the first SKIP number of attempts from the average due to initial JIT optimization/slowness.
            // After a few attempts, the JVM should be relatively optimized and the subsequent
            // PBE hashing times are the ones we want to include in our analysis
            boolean warmedUp = i >= SKIP;

            // how close we were on this hashing attempt to reach our desiredMillis target:
            // A number under 1 means we weren't slow enough, a number greater than 1 means we were too slow:
            double durationPercentAchieved = (double) duration / (double) desiredMillis;

            // we only want to collect timing samples if :
            // 1. we're warmed up (to account for JIT optimization)
            // 2. The attempt time at least met (>=) the desiredMillis target
            boolean collectSample = warmedUp && duration >= desiredMillis;
            if (collectSample) {
                // For each attempt, the x axis is the workFactor, and the y axis is how long it took to compute:
                points.add(new Point(workFactor, duration));
                //System.out.println("Collected point: workFactor=" + workFactor + ", duration=" + duration + " ms, %achieved=" + durationPercentAchieved);
            } else {
                minWorkFactor = Math.max(minWorkFactor, workFactor);
                //System.out.println("      Excluding sample: workFactor=" + workFactor + ", duration=" + duration + " ms, %achieved=" + durationPercentAchieved);
            }

            // amount to increase or decrease the workFactor for the next hashing iteration.  We increase if
            // we haven't met the desired millisecond time, and decrease if we're over it a little too much, always
            // trying to stay in that desired timing sweet spot
            double percentAdjust = workFactor * 0.0075; // 3/4ths of a percent
            if (durationPercentAchieved < 1d) {
                // Under target.  Let's increase by the amount that should get right at (or near) 100%:
                double ratio = desiredMillis / (double) duration;
                if (ratio > 1) {
                    double result = workFactor * ratio;
                    workFactor = (int) result;
                } else {
                    double difference = workFactor * (1 - durationPercentAchieved);
                    workFactor += Math.max(percentAdjust, difference);
                }
            } else if (durationPercentAchieved > 1.01d) {
                // Over target. Let's decrease gently to get closer.
                double difference = workFactor * (durationPercentAchieved - 1.01);
                difference = Math.min(percentAdjust, difference);
                // math.max here because the min allowed is 1000 per the JWA RFC, so we never want to go below that.
                workFactor = (int) Math.max(1000, workFactor - difference);
            } else {
                // we're at our target (desiredMillis); let's increase by a teeny bit to see where we get
                // (and the JVM might optimize with the same inputs, so we want to prevent that here)
                workFactor += 100;
            }
        }

        // We've collected all of our samples, now let's find the workFactor average number
        // That average is the best estimate for ensuring PBE hashes for the specified algorithm meet the
        // desiredMillis target on the current JVM/CPU platform:
        double sumX = 0;
        for (Point p : points) {
            sumX += p.x;
        }
        double average = sumX / points.size();
        //ensure our average is at least as much as the smallest work factor that got us closest to desiredMillis:
        return (int) Math.max(average, minWorkFactor);
    }

    private static class Point {
        long x;
        long y;
        double lnY;

        public Point(long x, long y) {
            this.x = x;
            this.y = y;
            this.lnY = Math.log((double) y);
        }
    }
     */
}
