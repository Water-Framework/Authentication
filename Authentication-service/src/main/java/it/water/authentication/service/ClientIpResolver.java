package it.water.authentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * #34/#37 - Resolves the client IP used as the per-IP lockout key dimension.
 * X-Forwarded-For / X-Real-IP are client-controlled and are honored ONLY when the immediate TCP peer
 * is a configured trusted proxy (water.authentication.trusted.proxies). With the default empty set the
 * forwarding headers are never trusted and the direct TCP source address is always used. The two REST
 * runtimes (JAX-RS/CXF with javax servlet, Spring MVC with jakarta servlet) extract the raw values from
 * their own request type and delegate the trust decision here, so the policy lives in one place.
 */
public final class ClientIpResolver {
    private static final Logger log = LoggerFactory.getLogger(ClientIpResolver.class);

    private ClientIpResolver() {
    }

    /**
     * @param trustedProxies set of trusted proxy IPs (never null; pass an empty set to trust none)
     * @param tcpSource immediate TCP peer address (getRemoteAddr()), or null if unavailable
     * @param forwardedFor raw X-Forwarded-For header value (may be null)
     * @param realIp raw X-Real-IP header value (may be null)
     * @return the resolved client IP, or null if it cannot be determined (the caller/system layer
     *         treats null as "unknown")
     */
    public static String resolve(Set<String> trustedProxies, String tcpSource, String forwardedFor, String realIp) {
        Set<String> proxies = (trustedProxies != null) ? trustedProxies : Set.of();
        if (tcpSource != null && proxies.contains(tcpSource)) {
            if (forwardedFor != null && !forwardedFor.isBlank()) {
                return forwardedFor.split(",")[0].trim();
            }
            if (realIp != null && !realIp.isBlank()) {
                return realIp.trim();
            }
        } else if (tcpSource == null && !proxies.isEmpty()) {
            // trusted proxies configured but peer unknown: fail closed, do not trust forwarded headers
            log.warn("Trusted proxies configured but TCP source address is unavailable; ignoring forwarding headers");
        }
        return tcpSource;
    }
}
