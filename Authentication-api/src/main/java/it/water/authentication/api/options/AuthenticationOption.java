package it.water.authentication.api.options;

import it.water.core.api.service.Service;

/**
 * @Author Aristide Cittadino
 * Define which issuer should be used to retrieve the right AuthenticationProvider.
 * If not issuer is defined the service will raise No Issuer defined exception
 */
public interface AuthenticationOption extends Service {
    String getIssuerName();
}
