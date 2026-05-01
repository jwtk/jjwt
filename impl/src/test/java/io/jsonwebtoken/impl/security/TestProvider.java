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

import java.security.Provider;

/**
 * Test-only {@link Provider} subclass. Defined in Java (not Groovy) because Groovy 4 cannot resolve
 * the {@code protected} {@code Provider} constructor via its meta-class on JDK 17+.
 */
public class TestProvider extends Provider {

    public TestProvider() {
        this("test");
    }

    public TestProvider(String name) {
        //noinspection deprecation - double constructor used for Java 8 source compatibility;
        // the (String, String, String) replacement was added in Java 9
        super(name, 1.0d, "info");
    }
}
