package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import java.lang.reflect.Constructor;

public class PropagatingExceptionFunction<T,R,E extends RuntimeException> implements Function<T,R> {

    private final Function<T,R> function;
    private final Class<E> clazz;
    private final String msg;

    public PropagatingExceptionFunction(Class<E> exceptionClass, String msg, Function<T, R> f) {
        this.function = Assert.notNull(f, "Function cannot be null.");
        this.clazz = Assert.notNull(exceptionClass, "Exception class cannot be null.");
        Assert.hasText(msg, "String message cannot be null or empty.");
        this.msg = msg;
    }

    @SuppressWarnings("unchecked")
    public R apply(T t) {
        try {
            return function.apply(t);
        } catch (Exception e) {
            if (clazz.isAssignableFrom(e.getClass())) {
                throw clazz.cast(e);
            }
            String msg = this.msg + " Cause: " + e.getMessage();
            Class<RuntimeException> clazzz = (Class<RuntimeException>)clazz;
            Constructor<RuntimeException> ctor = Classes.getConstructor(clazzz, String.class, Throwable.class);
            throw Classes.instantiate(ctor, msg, e);
        }
    }
}
