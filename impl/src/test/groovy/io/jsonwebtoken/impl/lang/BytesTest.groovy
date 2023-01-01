/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.impl.security.Randoms
import org.junit.Test

import java.security.MessageDigest

import static org.junit.Assert.*

class BytesTest {

    final static Random RANDOM = Randoms.secureRandom()

    @Test
    void testPrivateCtor() { // for code coverage only
        new Bytes()
    }

    @Test
    void testIntToBytesToInt() {
        int iterations = 10000
        for(int i = 0; i < iterations; i++) {
            int a = RANDOM.nextInt()
            byte[] bytes = Bytes.toBytes(a);
            int b = Bytes.toInt(bytes)
            assertEquals a, b
        }
    }

    @Test
    void testLongToBytesToLong() {
        int iterations = 10000
        for(int i = 0; i < iterations; i++) {
            long a = RANDOM.nextLong()
            byte[] bytes = Bytes.toBytes(a);
            long b = Bytes.toLong(bytes)
            assertEquals a, b
        }
    }

    @Test
    void testConcatNull() {
        byte[] output = Bytes.concat(null)
        assertNotNull output
        assertEquals 0, output.length
    }

    @Test
    void testConcatSingle() {
        byte[] bytes = new byte[32]
        RANDOM.nextBytes(bytes)
        byte[][] arg = [bytes] as byte[][]
        byte[] output = Bytes.concat(arg)
        assertTrue MessageDigest.isEqual(bytes, output)
    }

    @Test
    void testConcatSingleEmpty() {
        byte[] bytes = new byte[0]
        byte[][] arg = [bytes] as byte[][]
        byte[] output = Bytes.concat(arg)
        assertNotNull output
        assertEquals 0, output.length
    }

    @Test
    void testConcatMultiple() {
        byte[] a = new byte[32]; RANDOM.nextBytes(a)
        byte[] b = new byte[16]; RANDOM.nextBytes(b)

        byte[] output = Bytes.concat(a, b)

        assertNotNull output
        assertEquals a.length + b.length, output.length

        byte[] partA = new byte[a.length]
        System.arraycopy(output, 0, partA, 0, a.length)
        assertTrue MessageDigest.isEqual(a, partA)

        byte[] partB = new byte[b.length]
        System.arraycopy(output, a.length, partB, 0, b.length)
        assertTrue MessageDigest.isEqual(b, partB)
    }

    @Test
    void testConcatMultipleWithOneEmpty() {

        byte[] a = new byte[32]; RANDOM.nextBytes(a)
        byte[] b = new byte[0]

        byte[] output = Bytes.concat(a, b)

        assertNotNull output
        assertEquals a.length + b.length, output.length

        byte[] partA = new byte[a.length]
        System.arraycopy(output, 0, partA, 0, a.length)
        assertTrue MessageDigest.isEqual(a, partA)

        byte[] partB = new byte[b.length]
        System.arraycopy(output, a.length, partB, 0, b.length)
        assertTrue MessageDigest.isEqual(b, partB)
    }

    @Test
    void testLength() {
        int len = 32
        assertEquals len, Bytes.length(new byte[len])
    }

    @Test
    void testLengthZero() {
        assertEquals 0, Bytes.length(new byte[0])
    }

    @Test
    void testLengthNull() {
        assertEquals 0, Bytes.length(null)
    }

    @Test
    void testBitLength() {
        int len = 32
        byte[] a = new byte[len]
        assertEquals len * Byte.SIZE, Bytes.bitLength(a)
    }

    @Test
    void testBitLengthZero() {
        assertEquals 0, Bytes.bitLength(new byte[0])
    }

    @Test
    void testBitLengthNull() {
        assertEquals 0, Bytes.bitLength(null)
    }

    @Test
    void testIncrement() {

        byte[] counter = Bytes.toBytes(0)
        for(int i = 0; i < 100; i++) {
            assertEquals i, Bytes.toInt(counter)
            Bytes.increment(counter)
        }

        counter = Bytes.toBytes(Integer.MAX_VALUE - 1)

        Bytes.increment(counter)
        assertEquals Integer.MAX_VALUE, Bytes.toInt(counter)

        //check correct integer overflow:
        Bytes.increment(counter)
        assertEquals Integer.MIN_VALUE, Bytes.toInt(counter)
    }

    @Test
    void testIncrementEmpty() {
        byte[] counter = new byte[0]
        Bytes.increment(counter)
        assertTrue MessageDigest.isEqual(new byte[0], counter)
    }
}
