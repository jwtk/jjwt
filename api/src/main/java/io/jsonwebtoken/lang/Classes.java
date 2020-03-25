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

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

/**
 * @since 0.1
 */
public final class Classes {

    private Classes() {} //prevent instantiation

    /**
     * @since 0.1
     */
    private static final ClassLoaderAccessor THREAD_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() throws Throwable {
            return Thread.currentThread().getContextClassLoader();
        }
    };

    /**
     * @since 0.1
     */
    private static final ClassLoaderAccessor CLASS_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() throws Throwable {
            return Classes.class.getClassLoader();
        }
    };

    /**
     * @since 0.1
     */
    private static final ClassLoaderAccessor SYSTEM_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() throws Throwable {
            return ClassLoader.getSystemClassLoader();
        }
    };

    /**
     * Attempts to load the specified class name from the current thread's
     * {@link Thread#getContextClassLoader() context class loader}, then the
     * current ClassLoader (<code>Classes.class.getClassLoader()</code>), then the system/application
     * ClassLoader (<code>ClassLoader.getSystemClassLoader()</code>, in that order.  If any of them cannot locate
     * the specified class, an <code>UnknownClassException</code> is thrown (our RuntimeException equivalent of
     * the JRE's <code>ClassNotFoundException</code>.
     *
     * @param fqcn the fully qualified class name to load
     * @return the located class
     * @throws UnknownClassException if the class cannot be found.
     */
    @SuppressWarnings("unchecked")
    public static <T> Class<T> forName(String fqcn) throws UnknownClassException {

        Class clazz = THREAD_CL_ACCESSOR.loadClass(fqcn);

        if (clazz == null) {
            clazz = CLASS_CL_ACCESSOR.loadClass(fqcn);
        }

        if (clazz == null) {
            clazz = SYSTEM_CL_ACCESSOR.loadClass(fqcn);
        }

        if (clazz == null) {
            String msg = "Unable to load class named [" + fqcn + "] from the thread context, current, or " +
                    "system/application ClassLoaders.  All heuristics have been exhausted.  Class could not be found.";

            if (fqcn != null && fqcn.startsWith("io.jsonwebtoken.impl")) {
                msg += "  Have you remembered to include the jjwt-impl.jar in your runtime classpath?";
            }

            throw new UnknownClassException(msg);
        }

        return clazz;
    }

    /**
     * Returns the specified resource by checking the current thread's
     * {@link Thread#getContextClassLoader() context class loader}, then the
     * current ClassLoader (<code>Classes.class.getClassLoader()</code>), then the system/application
     * ClassLoader (<code>ClassLoader.getSystemClassLoader()</code>, in that order, using
     * {@link ClassLoader#getResourceAsStream(String) getResourceAsStream(name)}.
     *
     * @param name the name of the resource to acquire from the classloader(s).
     * @return the InputStream of the resource found, or <code>null</code> if the resource cannot be found from any
     * of the three mentioned ClassLoaders.
     * @since 0.8
     */
    public static InputStream getResourceAsStream(String name) {

        InputStream is = THREAD_CL_ACCESSOR.getResourceStream(name);

        if (is == null) {
            is = CLASS_CL_ACCESSOR.getResourceStream(name);
        }

        if (is == null) {
            is = SYSTEM_CL_ACCESSOR.getResourceStream(name);
        }

        return is;
    }

    public static boolean isAvailable(String fullyQualifiedClassName) {
        try {
            forName(fullyQualifiedClassName);
            return true;
        } catch (UnknownClassException e) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T newInstance(String fqcn) {
        return (T)newInstance(forName(fqcn));
    }

    public static <T> T newInstance(String fqcn, Class[] ctorArgTypes, Object... args) {
        Class<T> clazz = forName(fqcn);
        Constructor<T> ctor = getConstructor(clazz, ctorArgTypes);
        return instantiate(ctor, args);
    }

    @SuppressWarnings("unchecked")
    public static <T> T newInstance(String fqcn, Object... args) {
        return (T)newInstance(forName(fqcn), args);
    }

    public static <T> T newInstance(Class<T> clazz) {
        if (clazz == null) {
            String msg = "Class method parameter cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        try {
            return clazz.newInstance();
        } catch (Exception e) {
            throw new InstantiationException("Unable to instantiate class [" + clazz.getName() + "]", e);
        }
    }

    public static <T> T newInstance(Class<T> clazz, Object... args) {
        Class[] argTypes = new Class[args.length];
        for (int i = 0; i < args.length; i++) {
            argTypes[i] = args[i].getClass();
        }
        Constructor<T> ctor = getConstructor(clazz, argTypes);
        return instantiate(ctor, args);
    }

    public static <T> Constructor<T> getConstructor(Class<T> clazz, Class... argTypes) {
        try {
            return clazz.getConstructor(argTypes);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }

    }

    public static <T> T instantiate(Constructor<T> ctor, Object... args) {
        try {
            return ctor.newInstance(args);
        } catch (Exception e) {
            String msg = "Unable to instantiate instance with constructor [" + ctor + "]";
            throw new InstantiationException(msg, e);
        }
    }

    /**
     * @since 0.10.0
     */
    @SuppressWarnings("unchecked")
    public static <T> T invokeStatic(String fqcn, String methodName, Class[] argTypes, Object... args) {
        try {
            Class clazz = Classes.forName(fqcn);
            Method method = clazz.getDeclaredMethod(methodName, argTypes);
            method.setAccessible(true);
            return(T)method.invoke(null, args);
        } catch (Exception e) {
            String msg = "Unable to invoke class method " + fqcn + "#" + methodName + ".  Ensure the necessary " +
                "implementation is in the runtime classpath.";
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * @since 1.0
     */
    private static interface ClassLoaderAccessor {
        Class loadClass(String fqcn);

        InputStream getResourceStream(String name);
    }

    /**
     * @since 1.0
     */
    private static abstract class ExceptionIgnoringAccessor implements ClassLoaderAccessor {

        public Class loadClass(String fqcn) {
            Class clazz = null;
            ClassLoader cl = getClassLoader();
            if (cl != null) {
                try {
                    clazz = cl.loadClass(fqcn);
                } catch (ClassNotFoundException e) {
                    //Class couldn't be found by loader
                }
            }
            return clazz;
        }

        public InputStream getResourceStream(String name) {
            InputStream is = null;
            ClassLoader cl = getClassLoader();
            if (cl != null) {
                is = cl.getResourceAsStream(name);
            }
            return is;
        }

        protected final ClassLoader getClassLoader() {
            try {
                return doGetClassLoader();
            } catch (Throwable t) {
                //Unable to get ClassLoader
            }
            return null;
        }

        protected abstract ClassLoader doGetClassLoader() throws Throwable;
    }
}

