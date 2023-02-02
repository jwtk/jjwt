package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Classes;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class OptionalMethodInvoker<T, R> implements Function<T, R> {

    public static final String ERR_MSG = "Reflection class and method both exist, but the method cannot be invoked. " +
            "This is likely due to an internal implementation programming error.  Please report this to the " +
            "JJWT development team.  Cause: ";
    private final Class<?> CLASS;
    private final Method METHOD;

    public OptionalMethodInvoker(String fqcn, String methodName) {
        Class<?> clazz = null;
        Method method = null;
        try {
            clazz = Classes.forName(fqcn);
            method = clazz.getMethod(methodName, (Class<?>[]) null);
        } catch (Exception ignored) {
        }
        this.CLASS = clazz;
        this.METHOD = method;
    }

    // Visible for testing
    protected Object invoke(T t) throws InvocationTargetException, IllegalAccessException {
        return METHOD.invoke(t);
    }

    @SuppressWarnings("unchecked")
    @Override
    public R apply(T t) {
        R result = null;
        if (CLASS != null && METHOD != null && CLASS.isInstance(t)) {
            try {
                result = (R) invoke(t);
            } catch (Throwable throwable) {
                // should never happen if both CLASS and METHOD were found and 't' is the expected type:
                String msg = ERR_MSG + throwable.getMessage();
                throw new IllegalStateException(msg, throwable);
            }
        }
        return result;
    }
}
