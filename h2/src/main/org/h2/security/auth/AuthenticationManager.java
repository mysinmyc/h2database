/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth;

import org.h2.engine.Database;
import org.h2.engine.InternalAuthenticator;
import org.h2.engine.SysProperties;
import org.h2.engine.User;
import org.h2.message.DbException;
import org.h2.security.auth.spi.Authenticator;

/**
 * Authentication manager is responsible for the authentication of incoming users starting from connection informations provided
 * 
 * by default it validate user and password hash locally
 * 
 * To support external authentication providers is 
 *    - configur
 */
public class AuthenticationManager {

    private static AuthenticationManager INSTANCE = new AuthenticationManager();

    private AuthenticationManager() {
    }

    public static AuthenticationManager getInstance() {
        return INSTANCE;
    }

    Authenticator authenticator = null;

    boolean initialized = false;

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
        initialized = true;
    }

    private String getAuthenticatorClassNameFrom(String authenticatorString) {
        if (authenticatorString==null || authenticatorString.isEmpty()) {
            return null;
        }
        switch (authenticatorString) {
        case "no":
        case "disable":
        case "false":
            return null;
        case "yes":
        case "true":
        case "default":
            return "org.h2.security.auth.DefaultAuthenticator";
        default:
            return authenticatorString;
        }
    }

    public void setAuthenticatorString(String authenticatorString) {
        try {
            String authenticatorClassName=getAuthenticatorClassNameFrom(authenticatorString);
            setAuthenticator(authenticatorClassName == null ? null
                    : (Authenticator) Class.forName(authenticatorClassName).newInstance());
        } catch (Exception e) {
            throw DbException.convert(e);
        }
    }

    /*
     * by default initializes authenticator from h2.authenticator system propertye
     */
    private void init() {
        if (initialized) {
            return;
        }
        setAuthenticatorString(SysProperties.AUTHENTICATOR);
        initialized = true;
    }

    /**
     * Perform credentials authentication (validation and authorization)
     */
    public User authenticate(AuthenticationInfo authenticationInfo, Database database) throws AuthenticationException {
        try {
            if (SysProperties.ALLOW_INTERNAL_USERS
                    && authenticationInfo.getRealm() == null) {
                return InternalAuthenticator.INSTANCE.authenticate(authenticationInfo, database);
            }
            init();
            if (authenticator == null) {
                throw new AuthenticationException("no Authenticator available");
            }
            return authenticator.authenticate(authenticationInfo, database);
        } finally {
            authenticationInfo.clean();
        }
    }

}
