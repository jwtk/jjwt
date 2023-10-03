/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jsonwebtoken.impl.io;

/**
 * Defines encoding and decoding policies.
 *
 * @since 0.12.0, copied from
 * <a href="https://github.com/apache/commons-codec/tree/585497f09b026f6602daf986723a554e051bdfe6">commons-codec
 * 585497f09b026f6602daf986723a554e051bdfe6</a>
 */
enum CodecPolicy {

    /**
     * The strict policy. Data that causes a codec to fail should throw an exception.
     */
    STRICT,

    /**
     * The lenient policy. Data that causes a codec to fail should not throw an exception.
     */
    LENIENT
}
