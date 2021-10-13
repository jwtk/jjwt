package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.DefaultJweHeader;
import io.jsonwebtoken.impl.IdRegistry;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.EncryptionAlgorithms;
import io.jsonwebtoken.security.EstimateIterationsResult;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.PbeKey;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@SuppressWarnings({"unused"}) // reflection bridge class for the io.jsonwebtoken.security.KeyAlgorithms implementation
public final class KeyAlgorithmsBridge {

    // prevent instantiation
    private KeyAlgorithmsBridge() {
    }

    private static final String RSA1_5_ID = "RSA1_5";
    private static final String RSA1_5_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String RSA_OAEP_ID = "RSA-OAEP";
    private static final String RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String RSA_OAEP_256_ID = "RSA-OAEP-256";
    private static final String RSA_OAEP_256_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final AlgorithmParameterSpec RSA_OAEP_256_SPEC =
        new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    //For parser implementation - do not expose outside the impl module
    public static final Registry<String, KeyAlgorithm<?, ?>> REGISTRY;

    static {
        REGISTRY = new IdRegistry<>(Collections.<KeyAlgorithm<?, ?>>of(
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
            new DefaultRsaKeyAlgorithm<>(RSA1_5_ID, RSA1_5_TRANSFORMATION),
            new DefaultRsaKeyAlgorithm<>(RSA_OAEP_ID, RSA_OAEP_TRANSFORMATION),
            new DefaultRsaKeyAlgorithm<>(RSA_OAEP_256_ID, RSA_OAEP_256_TRANSFORMATION, RSA_OAEP_256_SPEC)
        ));
    }

    public static Collection<KeyAlgorithm<?, ?>> values() {
        return REGISTRY.values();
    }

    public static KeyAlgorithm<?, ?> findById(String id) {
        return REGISTRY.apply(id);
    }

    public static KeyAlgorithm<?, ?> forId(String id) {
        KeyAlgorithm<?, ?> instance = findById(id);
        if (instance == null) {
            String msg = "Unrecognized JWA KeyAlgorithm identifier: " + id;
            throw new UnsupportedJwtException(msg);
        }
        return instance;
    }

    private static KeyAlgorithm<PbeKey, SecretKey> lean(final Pbes2HsAkwAlgorithm alg) {

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
        return new KeyAlgorithm<PbeKey, SecretKey>() {
            @Override
            public KeyResult getEncryptionKey(KeyRequest<PbeKey> request) throws SecurityException {
                int iterations = request.getKey().getIterations();
                char[] password = request.getKey().getPassword();
                try {
                    alg.deriveKey(factory, password, rfcSalt, iterations);
                } catch (Exception e) {
                    throw new SecurityException("Unable to derive key", e);
                }
                return null;
            }

            @Override
            public SecretKey getDecryptionKey(DecryptionKeyRequest<SecretKey> request) throws SecurityException {
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

    private static char[] randomChars(int length) {
        char[] chars = new char[length];
        for (int i = 0; i < length; i++) {
            chars[i] = randomChar();
        }
        return chars;
    }

    public static EstimateIterationsResult estimateIterations(KeyAlgorithm<PbeKey, SecretKey> alg, long desiredMillis) {

        // The number of computational samples that land in our 'sweet spot' timing range matching desiredMillis.
        // These samples will be averaged and the final average will be the return value of this method
        // representing the number of iterations that should be taken for any given PBE hashing attempt to get
        // reasonably close to desiredMillis:
        final int NUM_SAMPLES = 30;
        final int SKIP = 3;
        // More important than the actual password (or characters) is the password length.
        // 8 characters is a commonly-found minimum required length in many systems circa 2021.
        final int PASSWORD_LENGTH = 8;

        final JweHeader HEADER = new DefaultJweHeader(); // not used during execution, needed to satisfy API call.
        final AeadAlgorithm ENC_ALG = EncryptionAlgorithms.A128GCM; // not used, needed to satisfy API

        if (alg instanceof Pbes2HsAkwAlgorithm) {
            // Strip away all things that cause time during computation except for the actual hashing algorithm:
            alg = lean((Pbes2HsAkwAlgorithm) alg);
        }

        EstimateIterationsResult ret = new EstimateIterationsResult(NUM_SAMPLES);

        int workFactor = 1000; // same as iterations for PBKDF2.  Different concept for Bcrypt/Scrypt
        int minWorkFactor = workFactor;
        List<Point> points = new ArrayList<>(NUM_SAMPLES);
        for (int i = 0; points.size() < NUM_SAMPLES; i++) {

            char[] password = randomChars(PASSWORD_LENGTH);
            PbeKey pbeKey = Keys.forPbe().setPassword(password).setIterations(workFactor).build();
            KeyRequest<PbeKey> request = new DefaultKeyRequest<>(null, null, pbeKey, HEADER, ENC_ALG);

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
                ret.addResult(workFactor, duration);
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
        ret.setEstimatedIterations((int) Math.max(average, minWorkFactor));
        return ret;
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
}
