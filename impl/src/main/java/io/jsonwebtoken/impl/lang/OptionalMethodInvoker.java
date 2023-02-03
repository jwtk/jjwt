package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Classes;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class OptionalMethodInvoker<T, R> extends ReflectionFunction<T, R> {

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

    @Override
    protected boolean supports(T input) {
        return CLASS != null && METHOD != null && CLASS.isInstance(input);
    }

    @SuppressWarnings("unchecked")
    @Override
    protected R invoke(T input) throws InvocationTargetException, IllegalAccessException {
        return (R) METHOD.invoke(input);
    }
}
