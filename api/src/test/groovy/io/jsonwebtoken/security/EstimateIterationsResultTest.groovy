package io.jsonwebtoken.security

import org.junit.Test
import org.junit.runner.RunWith
import static org.junit.Assert.*
import org.powermock.modules.junit4.PowerMockRunner

@RunWith(PowerMockRunner)
class EstimateIterationsResultTest {

    // for coverage
    @Test
    void testConstructor() {
        new EstimateIterationsResult()
        new EstimateIterationsResult(10)
    }

    @Test
    void testImmutable() {
        EstimateIterationsResult r = new EstimateIterationsResult()
        r.addResult(1, 1)
        try {
            def result = r.getResults()
            result.add(new EstimateIterationsResult.Result(2, 2))
            fail()
        } catch (Exception e) {
            assertTrue e instanceof UnsupportedOperationException
        }
    }

    @Test
    void testSetEstimateOnlyOnce() {
        EstimateIterationsResult r = new EstimateIterationsResult()
        r.setEstimatedIterations(1);
        try {
            r.setEstimatedIterations(1)
            fail()
        } catch (UnsupportedOperationException e) {
            assertEquals "Estimated iterations already set and can only be set once.", e.message
        }
    }
}
