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
package io.jsonwebtoken.impl

import org.junit.Test
import org.junit.runner.RunWith
import org.powermock.core.classloader.annotations.PrepareForTest
import org.powermock.modules.junit4.PowerMockRunner

import static org.junit.Assert.*

@RunWith(PowerMockRunner.class)
@PrepareForTest([System.class])
class DefaultTextCodecFactoryTest {

    @Test
    void testIsAndroidByVmName() {

        def factory = new DefaultTextCodecFactory() {
            @Override
            protected String getSystemProperty(String key) {
                return 'dalvik'
            }
        }

        assertTrue factory.getTextCodec() instanceof AndroidBase64Codec
    }

    @Test
    void testIsAndroidByNullVmName() {

        def factory = new DefaultTextCodecFactory() {
            @Override
            protected String getSystemProperty(String key) {
                if (key == 'java.vm.name') return null;
                return 'android'
            }
        }

        assertTrue factory.getTextCodec() instanceof AndroidBase64Codec
    }

    @Test
    void testIsAndroidByNullVmNameAndNullVendorName() {

        def factory = new DefaultTextCodecFactory() {
            @Override
            protected String getSystemProperty(String key) {
                return null
            }
        }

        assertFalse factory.getTextCodec() instanceof AndroidBase64Codec
    }
}
