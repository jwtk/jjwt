package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Condition;
import io.jsonwebtoken.lang.Classes;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @since JJWT_RELEASE_VERSION
 */
final class Providers {

    private static final String BC_PROVIDER_CLASS_NAME = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    static final boolean BOUNCY_CASTLE_AVAILABLE = Classes.isAvailable(BC_PROVIDER_CLASS_NAME);
    private static final AtomicReference<Provider> BC_PROVIDER = new AtomicReference<>();

    private Providers() {
    }

    private static Provider getBouncyCastleProviderIfPossible() {
        if (!BOUNCY_CASTLE_AVAILABLE) {
            return null;
        }
        Provider provider = BC_PROVIDER.get();
        if (provider == null) {

            Class<Provider> clazz = Classes.forName(BC_PROVIDER_CLASS_NAME);

            //check to see if the user has already registered the BC provider:
            Provider[] providers = Security.getProviders();
            for (Provider aProvider : providers) {
                if (clazz.isInstance(aProvider)) {
                    BC_PROVIDER.set(aProvider);
                    return aProvider;
                }
            }

            //user hasn't created the BC provider, so we'll create one just for JJWT's needs:
            provider = Classes.newInstance(clazz);
            BC_PROVIDER.set(provider);
        }
        return provider;
    }

    /**
     * Returns the BouncyCastle provider if and only if the specified Condition evaluates to {@code true}
     * <em>and</em> BouncyCastle is available.  Returns {@code null} otherwise.
     * <p>
     * If the condition evaluates to true and the JVM runtime already has BouncyCastle registered
     * (e.g. {@code Security.addProvider(bcProvider)}, that Provider instance will be found and returned.
     * If an existing BC provider is not found, a new BC instance will be created, cached for future reference,
     * and returned.
     * <p>
     * If a new BC provider is created and returned, it is <em>not</em> registered in the JVM via
     * {@code Security.addProvider} to ensure JJWT doesn't interfere with the application security provider
     * configuration and/or expectations.
     *
     * @param c condition to evaluate
     * @return any available BouncyCastle Provider if {@code c} evaluates to true, or {@code null} if either
     * {@code c} evaluates to false, or BouncyCastle is not available.
     */
    public static Provider getBouncyCastle(Condition c) {
        if (c.test()) {
            return getBouncyCastleProviderIfPossible();
        }
        return null;
    }
}
