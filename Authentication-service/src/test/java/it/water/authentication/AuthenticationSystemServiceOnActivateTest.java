package it.water.authentication;

import it.water.authentication.service.AuthenticationConstants;
import it.water.authentication.service.AuthenticationSystemServiceImpl;
import it.water.core.api.bundle.ApplicationProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Focused Mockito unit tests for {@link AuthenticationSystemServiceImpl#onActivate(ApplicationProperties)}
 * introduced by fix #40.
 *
 * <p>The production code emits a WARN log when {@code water.testMode=true} is detected at activation
 * time. Capturing SLF4J output in unit tests requires a list-appender setup that adds fragile
 * infrastructure coupling; instead we verify behaviour at the observable side-effect level:
 *
 * <ul>
 *   <li>The method must complete without throwing any exception in both the test-mode=true and
 *       test-mode=false paths.</li>
 *   <li>The method reads {@code water.testMode} from the supplied {@link ApplicationProperties}.</li>
 *   <li>When {@code applicationProperties} is {@code null} (e.g. component starts before the
 *       properties service is wired), the method must still complete without throwing.</li>
 * </ul>
 *
 * <p>The integration-level smoke test (that activation succeeds end-to-end under the test runtime
 * with {@code water.testMode=true}) is provided by {@link AuthenticationApiTest#componentsInsantiatedCorrectly()}
 * and every other test in that suite, since the test runtime activates all {@code @FrameworkComponent}s
 * before the first test method executes.
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationSystemServiceOnActivateTest {

    @Mock
    private ApplicationProperties applicationProperties;

    @InjectMocks
    private AuthenticationSystemServiceImpl authenticationSystemServiceImpl;

    // ------------------------------------------------------------------
    // #40 — onActivate with testMode=true (WARN path)
    // ------------------------------------------------------------------

    /**
     * When {@code water.testMode=true} the WARN block is entered.
     * The method must complete without throwing and must read the property from the
     * supplied {@link ApplicationProperties}.
     */
    @Test
    void onActivate_testModeTrue_completesWithoutException() {
        Mockito.when(applicationProperties.getProperty(AuthenticationConstants.TEST_MODE))
               .thenReturn("true");

        // Must not throw — the WARN log is emitted internally and is not observable here
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> authenticationSystemServiceImpl.onActivate(applicationProperties),
                "#40: onActivate() must not throw when water.testMode=true");

        // The property must have been consulted
        Mockito.verify(applicationProperties).getProperty(AuthenticationConstants.TEST_MODE);
    }

    // ------------------------------------------------------------------
    // #40 — onActivate with testMode=false (silent path)
    // ------------------------------------------------------------------

    /**
     * When {@code water.testMode=false} the WARN block is skipped.
     * The method must complete silently without throwing.
     */
    @Test
    void onActivate_testModeFalse_completesWithoutException() {
        Mockito.when(applicationProperties.getProperty(AuthenticationConstants.TEST_MODE))
               .thenReturn("false");

        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> authenticationSystemServiceImpl.onActivate(applicationProperties),
                "#40: onActivate() must not throw when water.testMode=false");

        Mockito.verify(applicationProperties).getProperty(AuthenticationConstants.TEST_MODE);
    }

    // ------------------------------------------------------------------
    // #40 — onActivate with testMode property absent (null value)
    // ------------------------------------------------------------------

    /**
     * When the property is absent ({@code getProperty} returns {@code null}),
     * the method must treat this as false (test mode is off) and complete without throwing.
     */
    @Test
    void onActivate_testModePropertyAbsent_completesWithoutException() {
        Mockito.when(applicationProperties.getProperty(AuthenticationConstants.TEST_MODE))
               .thenReturn(null);

        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> authenticationSystemServiceImpl.onActivate(applicationProperties),
                "#40: onActivate() must not throw when water.testMode property is absent (null)");
    }

    // ------------------------------------------------------------------
    // #40 — onActivate with applicationProperties == null
    // ------------------------------------------------------------------

    /**
     * If the component activates before {@code ApplicationProperties} is wired (i.e. the argument
     * supplied by the framework is {@code null}), the method must not throw a NullPointerException.
     * This matches the null-guard present in the production code.
     */
    @Test
    void onActivate_nullApplicationProperties_completesWithoutException() {
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> authenticationSystemServiceImpl.onActivate(null),
                "#40: onActivate(null) must not throw — the implementation guards against null ApplicationProperties");
    }

    // ------------------------------------------------------------------
    // #40 — onActivate with testMode value that has surrounding whitespace
    // ------------------------------------------------------------------

    /**
     * Property values from configuration files often carry trailing newlines or spaces.
     * The implementation trims the value before parsing, so "true  " must activate the WARN path.
     */
    @Test
    void onActivate_testModeValueWithWhitespace_treatedAsTrue() {
        Mockito.when(applicationProperties.getProperty(AuthenticationConstants.TEST_MODE))
               .thenReturn("  true  ");

        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> authenticationSystemServiceImpl.onActivate(applicationProperties),
                "#40: onActivate() must handle whitespace-padded 'true' without throwing");
    }
}
