package it.water.authentication.service;

import it.water.authentication.api.options.AuthenticationOption;
import it.water.authentication.service.execption.NoIssuerNameDefinedException;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.interceptors.annotations.FrameworkComponent;
import it.water.core.interceptors.annotations.Inject;
import lombok.Setter;

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
}
