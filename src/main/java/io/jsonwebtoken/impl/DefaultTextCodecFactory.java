/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

public class DefaultTextCodecFactory implements TextCodecFactory {

    protected String getSystemProperty(String key) {
        return System.getProperty(key);
    }

    protected boolean isAndroid() {

        String name = getSystemProperty("java.vm.name");
        if (name != null) {
            String lcase = name.toLowerCase();
            return lcase.contains("dalvik");
        }

        name = getSystemProperty("java.vm.vendor");
        if (name != null) {
            String lcase = name.toLowerCase();
            return lcase.contains("android");
        }

        return false;
    }


    @Override
    public TextCodec getTextCodec() {

        if (isAndroid()) {
            return new AndroidBase64Codec();
        }

        return new Base64Codec();
    }
}
