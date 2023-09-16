/*
 * Copyright © 2020 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.lang.Assert;

public class LocatorFunction<T> implements Function<Header, T> {

    private final Locator<T> locator;

    public LocatorFunction(Locator<T> locator) {
        this.locator = Assert.notNull(locator, "Locator instance cannot be null.");
    }

    @Override
    public T apply(Header h) {
        return this.locator.locate(h);
    }
}
