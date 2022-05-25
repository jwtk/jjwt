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
package io.jsonwebtoken.lang;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * No longer used by JJWT.  Will be removed before the 1.0 final release.
 *
 * @deprecated since JJWT_RELEASE_VERSION. will be removed before the 1.0 final release.
 */
@Deprecated
public final class RuntimeEnvironment {

    private RuntimeEnvironment() {
    } //prevent instantiation

    private static final String BC_PROVIDER_CLASS_NAME = "org.bouncycastle.jce.provider.BouncyCastleProvider";

    private static final AtomicBoolean bcLoaded = new AtomicBoolean(false);

    /**
     * {@code true} if BouncyCastle is in the runtime classpath, {@code false} otherwise.
     *
     * @deprecated since JJWT_RELEASE_VERSION. will be removed before the 1.0 final release.
     */
    @Deprecated
    public static final boolean BOUNCY_CASTLE_AVAILABLE = Classes.isAvailable(BC_PROVIDER_CLASS_NAME);

    /**
     * Register BouncyCastle as a JCA provider in the system's {@link Security#getProviders() Security Providers} list
     * if BouncyCastle is in the runtime classpath.
     *
     * @deprecated since JJWT_RELEASE_VERSION. will be removed before the 1.0 final release.
     */
    @Deprecated
    public static void enableBouncyCastleIfPossible() {

        if (!BOUNCY_CASTLE_AVAILABLE || bcLoaded.get()) {
            return;
        }

        try {
            Class<Provider> clazz = Classes.forName(BC_PROVIDER_CLASS_NAME);

            //check to see if the user has already registered the BC provider:

            Provider[] providers = Security.getProviders();

            for (Provider provider : providers) {
                if (clazz.isInstance(provider)) {
                    bcLoaded.set(true);
                    return;
                }
            }

            //bc provider not enabled - add it:
            Provider provider = Classes.newInstance(clazz);
            Security.addProvider(provider);
            bcLoaded.set(true);

        } catch (UnknownClassException e) {
            //not available
        }
    }

    static {
        enableBouncyCastleIfPossible();
    }

}
