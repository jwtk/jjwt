/*
 * Copyright (C) 2019 jsonwebtoken.io
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
package io.jsonwebtoken.impl.io

class FakeServiceDescriptorClassLoader extends ClassLoader {
    private String serviceDescriptor

    FakeServiceDescriptorClassLoader(ClassLoader parent, String serviceDescriptor) {
        super(parent)
        this.serviceDescriptor = serviceDescriptor
    }

    @Override
    Enumeration<URL> getResources(String name) throws IOException {
        if (name.startsWith("META-INF/services/")) {
            return super.getResources(serviceDescriptor)
        } else {
            return super.getResources(name)
        }
    }

    static void runWithFake(String fakeDescriptor, Closure closure) {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader()
        try {
            Thread.currentThread().setContextClassLoader(new FakeServiceDescriptorClassLoader(originalClassLoader, fakeDescriptor))
            closure.run()
        } finally {
            if(originalClassLoader != null) {
                Thread.currentThread().setContextClassLoader(originalClassLoader)
            }
        }
    }
}