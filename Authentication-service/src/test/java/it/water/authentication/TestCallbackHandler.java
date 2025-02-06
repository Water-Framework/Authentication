package it.water.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.io.IOException;
import java.security.Principal;
import java.util.Optional;

public class TestCallbackHandler implements CallbackHandler {
    private Logger log = LoggerFactory.getLogger(TestCallbackHandler.class);
    private Subject subject;

    public TestCallbackHandler(Subject subject) {
        this.subject = subject;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException {
        Optional<Principal> usernameOpt = this.subject.getPrincipals().stream().findFirst();
        Optional<Object> passwordOpt = this.subject.getPrivateCredentials().stream().findFirst();
        try {
            if (usernameOpt.isPresent() && passwordOpt.isPresent()) {
                String username = usernameOpt.get().getName();
                String password = passwordOpt.get().toString();
                //updating callbacks
                ((NameCallback) callbacks[0]).setName(username);
                ((PasswordCallback) callbacks[1]).setPassword(password.toCharArray());
                return;
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        throw new IOException("Login failed");
    }
}
