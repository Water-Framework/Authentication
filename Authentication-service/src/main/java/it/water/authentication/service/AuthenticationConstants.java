package it.water.authentication.service;

public class AuthenticationConstants {

    private AuthenticationConstants() {
    }

    public static final String AUTHENTICATION_ISSUER_NAME = "water.authentication.service.issuer";

    public static final String KEYSTORE_PASSWORD = "water.keystore.password";
    public static final String KEYSTORE_ALIAS = "water.keystore.alias";
    public static final String KEYSTORE_FILE = "water.keystore.file";
    public static final String PRIVATE_KEY_PASSWORD = "water.private.key.password";

    //Framework-wide test mode flag; when true lockout enforcement is disabled
    public static final String TEST_MODE = "water.testMode";

    //H9 - login lockout configuration
    public static final String LOGIN_LOCKOUT_THRESHOLD = "water.authentication.login.lockout.threshold";
    public static final String LOGIN_LOCKOUT_WINDOW_MILLIS = "water.authentication.login.lockout.window.millis";
    public static final String LOGIN_LOCKOUT_DURATION_MILLIS = "water.authentication.login.lockout.duration.millis";
    //M33 - hard cap on tracked keys in the in-memory store to bound memory usage
    public static final String LOGIN_LOCKOUT_MAX_KEYS = "water.authentication.login.lockout.max.keys";

    //#34 - progressive backoff
    public static final String LOGIN_LOCKOUT_BACKOFF_ENABLED = "water.authentication.login.lockout.backoff.enabled";
    public static final String LOGIN_LOCKOUT_BACKOFF_MULTIPLIER = "water.authentication.login.lockout.backoff.multiplier";
    public static final String LOGIN_LOCKOUT_MAX_DURATION_MILLIS = "water.authentication.login.lockout.max.duration.millis";

    //#34/#37 - trusted reverse proxies
    public static final String TRUSTED_PROXIES = "water.authentication.trusted.proxies";

    //Multitenancy - when true this issuer runs in MT mode: login resolves/validates the active company
    //and the token carries the companyId claim. Default false = single-tenant/legacy behavior.
    public static final String MULTITENANT_ENABLED = "water.authentication.multitenant.enabled";
}
