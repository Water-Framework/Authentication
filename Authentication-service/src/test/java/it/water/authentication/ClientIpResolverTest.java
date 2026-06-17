/*
 * Copyright 2024 Aristide Cittadino
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
package it.water.authentication;

import it.water.authentication.service.ClientIpResolver;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Set;

/**
 * Pure unit tests for {@link ClientIpResolver}.
 *
 * <p>ClientIpResolver is a stateless utility class (no Water runtime dependencies) so these tests
 * run with plain JUnit 5 — no WaterTestExtension needed.
 *
 * <p>The test cases directly mirror the specification in fix #34/#37:
 * <ul>
 *   <li>Untrusted proxy: always use tcpSource, never honour forwarding headers.</li>
 *   <li>Trusted proxy + X-Forwarded-For: first IP in the XFF list.</li>
 *   <li>Trusted proxy + no XFF, X-Real-IP present: X-Real-IP.</li>
 *   <li>Trusted proxy + no headers at all: tcpSource.</li>
 *   <li>tcpSource null + trustedProxies empty: return null.</li>
 *   <li>tcpSource null + trustedProxies non-empty: fail-closed (return null, no NPE).</li>
 *   <li>trustedProxies null: treated as empty (no NPE).</li>
 *   <li>XFF with whitespace and multiple IPs: trim and return first.</li>
 * </ul>
 */
class ClientIpResolverTest {

    // -----------------------------------------------------------------------
    // Untrusted proxy — forwarding headers must be ignored
    // -----------------------------------------------------------------------

    /**
     * When the TCP peer is NOT in the trusted-proxy set, the direct tcpSource is always used,
     * regardless of what X-Forwarded-For says.
     */
    @Test
    void resolve_untrustedProxy_returnsTcpSource() {
        String result = ClientIpResolver.resolve(
                Set.of("10.0.0.1"),   // trusted: only 10.0.0.1
                "1.2.3.4",            // TCP peer: untrusted
                "5.6.7.8",            // XFF — must be ignored
                "9.9.9.9"             // X-Real-IP — must be ignored
        );
        Assertions.assertEquals("1.2.3.4", result,
                "Untrusted TCP peer: tcpSource must be returned, forwarding headers must be ignored");
    }

    /**
     * When trustedProxies is empty (the default), no IP is ever a trusted proxy, so tcpSource is
     * always returned — even if XFF is set.
     */
    @Test
    void resolve_emptyTrustedProxies_returnsTcpSource() {
        String result = ClientIpResolver.resolve(
                Set.of(),             // empty → no trusted proxies
                "203.0.113.5",
                "192.0.2.1",          // XFF — ignored
                null
        );
        Assertions.assertEquals("203.0.113.5", result,
                "Empty trustedProxies: tcpSource must always be returned");
    }

    // -----------------------------------------------------------------------
    // Trusted proxy + XFF present
    // -----------------------------------------------------------------------

    /**
     * When the TCP peer IS a trusted proxy and XFF is present, the FIRST IP in the comma-separated
     * list is returned as the resolved client address.
     */
    @Test
    void resolve_trustedProxy_xffPresent_returnsFirstXffIp() {
        String result = ClientIpResolver.resolve(
                Set.of("10.0.0.1"),
                "10.0.0.1",           // trusted TCP peer
                "5.6.7.8, 10.0.0.1", // XFF with two IPs
                null
        );
        Assertions.assertEquals("5.6.7.8", result,
                "Trusted proxy + XFF: first IP in XFF list must be returned");
    }

    /**
     * XFF with surrounding whitespace around the first entry — the implementation must trim before
     * returning.
     */
    @Test
    void resolve_trustedProxy_xffWithSpaces_trimsAndReturnsFirstIp() {
        String result = ClientIpResolver.resolve(
                Set.of("10.0.0.1"),
                "10.0.0.1",
                "  1.1.1.1 , 2.2.2.2",   // leading/trailing spaces on first IP
                null
        );
        Assertions.assertEquals("1.1.1.1", result,
                "XFF with spaces: first IP must be trimmed before return");
    }

    /**
     * Single-entry XFF (no comma) — must still work correctly.
     */
    @Test
    void resolve_trustedProxy_xffSingleEntry_returnsThatIp() {
        String result = ClientIpResolver.resolve(
                Set.of("172.16.0.1"),
                "172.16.0.1",
                "198.51.100.77",
                null
        );
        Assertions.assertEquals("198.51.100.77", result,
                "Single-entry XFF: that entry must be returned without trailing comma artefacts");
    }

    // -----------------------------------------------------------------------
    // Trusted proxy + no XFF, X-Real-IP present
    // -----------------------------------------------------------------------

    /**
     * When TCP peer is trusted and XFF is absent (null), but X-Real-IP is present, X-Real-IP is used.
     */
    @Test
    void resolve_trustedProxy_noXff_realIpPresent_returnsRealIp() {
        String result = ClientIpResolver.resolve(
                Set.of("10.0.0.1"),
                "10.0.0.1",
                null,                  // no XFF
                "5.5.5.5"              // X-Real-IP present
        );
        Assertions.assertEquals("5.5.5.5", result,
                "Trusted proxy, no XFF, X-Real-IP present: X-Real-IP must be returned");
    }

    /**
     * When TCP peer is trusted and XFF is blank (not null), X-Real-IP must be used as fallback.
     */
    @Test
    void resolve_trustedProxy_blankXff_realIpPresent_returnsRealIp() {
        String result = ClientIpResolver.resolve(
                Set.of("10.0.0.1"),
                "10.0.0.1",
                "   ",                 // blank XFF — treated as absent
                "7.7.7.7"
        );
        Assertions.assertEquals("7.7.7.7", result,
                "Trusted proxy, blank XFF, X-Real-IP present: X-Real-IP must be returned");
    }

    // -----------------------------------------------------------------------
    // Trusted proxy + no forwarding headers → fall back to tcpSource
    // -----------------------------------------------------------------------

    /**
     * When TCP peer is trusted but neither XFF nor X-Real-IP is available, tcpSource is the best
     * available address and must be returned.
     */
    @Test
    void resolve_trustedProxy_noHeaders_returnsTcpSource() {
        String result = ClientIpResolver.resolve(
                Set.of("10.0.0.1"),
                "10.0.0.1",
                null,
                null
        );
        Assertions.assertEquals("10.0.0.1", result,
                "Trusted proxy with no forwarding headers: tcpSource itself must be returned");
    }

    // -----------------------------------------------------------------------
    // tcpSource null edge cases
    // -----------------------------------------------------------------------

    /**
     * tcpSource null + trustedProxies empty: no IP can be determined; null is returned.
     */
    @Test
    void resolve_nullTcpSource_emptyTrustedProxies_returnsNull() {
        String result = ClientIpResolver.resolve(
                Set.of(),
                null,
                "1.1.1.1",
                "2.2.2.2"
        );
        Assertions.assertNull(result,
                "tcpSource null + no trusted proxies: null must be returned");
    }

    /**
     * tcpSource null + trustedProxies non-empty: fail-closed path — forwarding headers are not
     * trusted because the TCP source is unknown, so null is returned (no NPE).
     */
    @Test
    void resolve_nullTcpSource_nonEmptyTrustedProxies_failsClosed_returnsNull() {
        String result = ClientIpResolver.resolve(
                Set.of("10.0.0.1"),
                null,                  // peer unknown
                "1.1.1.1",             // XFF — must be ignored (fail-closed)
                "2.2.2.2"              // X-Real-IP — must be ignored
        );
        Assertions.assertNull(result,
                "#37 fail-closed: when tcpSource is null and proxies are configured, null must be returned");
    }

    // -----------------------------------------------------------------------
    // trustedProxies null — treated as empty (no NPE)
    // -----------------------------------------------------------------------

    /**
     * null trustedProxies set must be treated identically to an empty set: no proxy is trusted,
     * tcpSource is returned, and no NullPointerException is thrown.
     */
    @Test
    void resolve_nullTrustedProxies_treatedAsEmpty_returnsTcpSource() {
        String result = ClientIpResolver.resolve(
                null,                  // null → treated as empty
                "203.0.113.99",
                "1.1.1.1",             // XFF — ignored (no trusted proxies)
                "2.2.2.2"
        );
        Assertions.assertEquals("203.0.113.99", result,
                "null trustedProxies must be treated as empty: tcpSource must be returned, no NPE");
    }

    /**
     * null trustedProxies + null tcpSource: both null — no exception, return null.
     */
    @Test
    void resolve_nullTrustedProxies_nullTcpSource_returnsNull() {
        Assertions.assertDoesNotThrow(() -> {
            String result = ClientIpResolver.resolve(null, null, "1.1.1.1", "2.2.2.2");
            Assertions.assertNull(result, "null proxies + null tcpSource: null must be returned");
        }, "resolve(null, null, ...) must not throw");
    }
}
