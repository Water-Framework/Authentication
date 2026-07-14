package it.water.authentication.api.options;

import it.water.core.api.service.Service;

import java.util.Set;

/**
 * @Author Aristide Cittadino
 * Define which issuer should be used to retrieve the right AuthenticationProvider.
 * If not issuer is defined the service will raise No Issuer defined exception
 */
public interface AuthenticationOption extends Service {
    String getIssuerName();

    /**
     * #34/#37 - Set of trusted reverse-proxy IPs. X-Forwarded-For / X-Real-IP are honored only when the
     * immediate TCP peer is in this set. Empty (default) means forwarding headers are never trusted and
     * only the direct TCP source address is used.
     * @return immutable set of trusted proxy IPs, never null
     */
    Set<String> getTrustedProxies();

    /**
     * Multitenancy enablement for this issuer. When true, login resolves/validates the active company
     * and the emitted token carries the companyId claim; when false the behavior is single-tenant/legacy
     * (any companyId supplied by the client is ignored). Reads water.authentication.multitenant.enabled.
     * @return true if multi-tenant mode is enabled (default false)
     */
    boolean isMultiTenantEnabled();
}
