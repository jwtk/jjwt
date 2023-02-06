/*
 * Copyright © 2021 jsonwebtoken.io
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

import io.jsonwebtoken.lang.Assert;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class Conditions {

    private Conditions() {
    }

    public static final Condition TRUE = of(true);

    public static Condition of(boolean val) {
        return new BooleanCondition(val);
    }

    public static Condition not(Condition c) {
        return new NotCondition(c);
    }

    public static Condition exists(CheckedSupplier<?> s) {
        return new ExistsCondition(s);
    }

    public static Condition notExists(CheckedSupplier<?> s) {
        return not(exists(s));
    }

    private static final class NotCondition implements Condition {

        private final Condition c;

        private NotCondition(Condition c) {
            this.c = Assert.notNull(c, "Condition cannot be null.");
        }

        @Override
        public boolean test() {
            return !c.test();
        }
    }

    private static final class BooleanCondition implements Condition {
        private final boolean value;

        public BooleanCondition(boolean value) {
            this.value = value;
        }

        @Override
        public boolean test() {
            return value;
        }
    }

    private static final class ExistsCondition implements Condition {
        private final CheckedSupplier<?> supplier;

        ExistsCondition(CheckedSupplier<?> supplier) {
            this.supplier = Assert.notNull(supplier, "CheckedSupplier cannot be null.");
        }

        @Override
        public boolean test() {
            Object value = null;
            try {
                value = supplier.get();
            } catch (Exception ignored) {
            }
            return value != null;
        }
    }
}
