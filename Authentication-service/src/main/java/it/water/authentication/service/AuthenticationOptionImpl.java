package it.water.authentication.service;

import it.water.authentication.api.options.AuthenticationOption;
import it.water.authentication.service.execption.NoIssuerNameDefinedException;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.interceptors.annotations.FrameworkComponent;
import it.water.core.interceptors.annotations.Inject;
import lombok.Setter;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

@FrameworkComponent
public class AuthenticationOptionImpl implements AuthenticationOption {

    @Inject
    @Setter
    private ApplicationProperties applicationProperties;

    @Override
    public String getIssuerName() {
        String value = (String) applicationProperties.getProperty(AuthenticationConstants.AUTHENTICATION_ISSUER_NAME);
        if (value == null)
            throw new NoIssuerNameDefinedException();
        return value;
    }

    @Override
    public Set<String> getTrustedProxies() {
        if (applicationProperties == null) {
            return Collections.emptySet();
        }
        Object raw = applicationProperties.getProperty(AuthenticationConstants.TRUSTED_PROXIES);
        String value = (raw == null) ? "" : raw.toString().trim();
        if (value.isEmpty()) {
            return Collections.emptySet();
        }
        Set<String> proxies = new LinkedHashSet<>();
        for (String token : value.split(",")) {
            String ip = token.trim();
            if (!ip.isEmpty()) {
                proxies.add(ip);
            }
        }
        return Collections.unmodifiableSet(proxies);
    }

    @Override
    public boolean isMultiTenantEnabled() {
        if (applicationProperties == null)
            return false;
        Object raw = applicationProperties.getProperty(AuthenticationConstants.MULTITENANT_ENABLED);
        return raw != null && Boolean.parseBoolean(raw.toString().trim());
    }
}
