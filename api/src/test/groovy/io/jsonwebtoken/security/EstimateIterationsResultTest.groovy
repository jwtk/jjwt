package io.jsonwebtoken.security

import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import static org.junit.Assert.*
import org.powermock.modules.junit4.PowerMockRunner

@RunWith(PowerMockRunner)
class EstimateIterationsResultTest {

    private EstimateIterationsResult estimateIterationsResult

    @Before
    void setup() {
        estimateIterationsResult = EstimateIterationsResult.builder()
            .addResult(1, 2)
            .setEstimatedIterations(3)
            .build()
    }

    @Test
    void testImmutable() {
        try {
            def result = estimateIterationsResult.getResults()
            result.add(new EstimateIterationsResult.Result(2, 2))
            fail()
        } catch (Exception e) {
            assertTrue e instanceof UnsupportedOperationException
        }
    }

    @Test
    void testExpectedValues() {
        assertEquals 1, estimateIterationsResult.results.get(0).workFactor
        assertEquals 2, estimateIterationsResult.results.get(0).duration
        assertEquals 3, estimateIterationsResult.estimatedIterations
    }
}
