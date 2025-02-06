package it.water.authentication;

import it.water.authentication.api.AuthenticationApi;
import it.water.authentication.service.jaas.AuthenticationModule;
import it.water.core.api.model.Role;
import it.water.core.api.security.Authenticable;

import java.security.Principal;
import java.util.List;
import java.util.Set;

public class TestAuthenticationModule extends AuthenticationModule {

    private AuthenticationApi authenticationApi;

    public TestAuthenticationModule(AuthenticationApi authenticationApi) {
        this.authenticationApi = authenticationApi;
    }

    @Override
    protected void setAdditionalPrincipals(Set<Principal> principals) {
        return;
    }

    @Override
    protected List<Role> getRoles(Authenticable authenticable) {
        return List.of();
    }

    @Override
    protected AuthenticationApi getAuthenticationApi() {
        return authenticationApi;
    }

    @Override
    protected void postAuthentication(Authenticable authenticated) {
        //do nothing
    }
}
