/*
 * Copyright 2019-2023 HyperIoT
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
 *
 */

package it.water.authentication.service.jaas;

import it.water.authentication.api.AuthenticationApi;
import it.water.core.api.model.Role;
import it.water.core.api.security.Authenticable;
import it.water.core.security.model.principal.RolePrincipal;
import it.water.core.security.model.principal.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.*;

/**
 * @author Aristide Cittadino Jaas Plugin for Authentication against HyperIoT
 * System.
 * Default Behaviour is only HUsers can login into the platform
 */
public abstract class AuthenticationModule implements LoginModule {
    private static Logger log = LoggerFactory.getLogger(AuthenticationModule.class.getName());

    protected Subject subject;
    protected CallbackHandler callbackHandler;
    protected String user;
    protected Authenticable loggedUser;
    protected final Set<Principal> principals = new HashSet<>();
    protected boolean loginSucceeded;
    protected List<String> groups;
    protected Collection<? extends Role> roles;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
        log.debug("Initializing HyperIoT Authentication Module...");
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        loginSucceeded = false;
        this.groups = new LinkedList<>();
        this.roles = new ArrayList<>();
    }


    @Override
    public boolean login() throws LoginException {
        log.debug("Invoking HyperIoTJAAS Login...");
        this.loggedUser = null;
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("Username: ");
        callbacks[1] = new PasswordCallback("Password: ", false);

        try {
            callbackHandler.handle(callbacks);
        } catch (IOException ioe) {
            throw new LoginException(ioe.getMessage());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException(
                    uce.getMessage() + " not available to obtain information from user");
        }

        user = ((NameCallback) callbacks[0]).getName();
        char[] tmpPassword = ((PasswordCallback) callbacks[1]).getPassword();

        if (tmpPassword == null) {
            tmpPassword = new char[0];
        }

        if (user == null) {
            throw new FailedLoginException("user name is null");
        }

        log.debug("Login attemp with username: {}", user);
        if (!authenticate(user, String.valueOf(tmpPassword))) {
            throw new FailedLoginException("Authentication failed");
        }

        loginSucceeded = true;

        return loginSucceeded;
    }

    @Override
    public boolean commit() throws LoginException {
        boolean result = this.doCommit();
        if (result) {
            subject.getPrincipals().addAll(principals);
        }
        clear();
        return result;
    }

    protected boolean doCommit() {
        log.debug(
                "Committing login for user {} login successed: {}", user, loginSucceeded);
        boolean result = loginSucceeded;
        if (result) {
            log.debug("Adding new Principal {}", this.loggedUser);

            principals.add(new UserPrincipal(this.loggedUser.getPassword(), this.loggedUser.isAdmin(), this.loggedUser.getLoggedEntityId(), this.loggedUser.getIssuer()));

            for (Role role : roles) {
                principals.add(new RolePrincipal(role.getName()));
            }

            setAdditionalPrincipals(principals);
        }
        return result;
    }

    @Override
    public boolean abort() throws LoginException {
        log.debug("Aborting...");
        clear();
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        log.debug("Logging out...");
        subject.getPrincipals().removeAll(principals);
        principals.clear();
        clear();
        return true;
    }

    private void clear() {
        user = null;
        loginSucceeded = false;
    }

    private boolean authenticate(String username, String password) {
        log.debug("Invoke authentication ....");
        try {
            this.loggedUser = this.login(username, password);
        } catch (Exception e) {
            this.loggedUser = null;
            log.warn("Error while logging in {}: {}", username, e.getMessage());
        }
        if (loggedUser == null || !loggedUser.isActive())
            return false;
        roles = getRoles(loggedUser);
        this.postAuthentication(loggedUser);
        return true;
    }

    private Authenticable login(String username, String password) throws FailedLoginException {
        try {
            return getAuthenticationApi().login(username, password);
        } catch (Exception e) {
            throw new FailedLoginException(e.getMessage());
        }
    }

    /**
     * @param authenticated
     */
    protected abstract void postAuthentication(Authenticable authenticated);

    /**
     * Add more principals after login successed
     *
     * @param principals
     */
    protected abstract void setAdditionalPrincipals(Set<Principal> principals);

    /**
     * Retrieve Roles for specific issuer
     *
     * @param authenticable
     * @return
     */
    protected abstract List<Role> getRoles(Authenticable authenticable);

    /**
     * Based on runtime.
     *
     * @return
     */
    protected abstract AuthenticationApi getAuthenticationApi();

}
