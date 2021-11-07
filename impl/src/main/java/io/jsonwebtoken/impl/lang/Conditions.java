package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class Conditions {

    private Conditions() {
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
