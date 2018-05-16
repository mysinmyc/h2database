/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth.impl;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;

import org.h2.security.auth.AuthenticationInfo;
import org.h2.security.auth.ConfigProperties;
import org.h2.security.auth.spi.CredentialsValidator;

/**
 * Validate credentials by using standard javax.security.auth API
 * 
 * configuration parameters:
 *    loginContextName = name of login context
 *
 */
public class JavaxSecurityAuthCredentialsValidator implements CredentialsValidator {

    String loginContextName;

    @Override
    public void configure(ConfigProperties configProperties) {
        loginContextName=configProperties.getStringValue("loginContextloginContextName",null);
    }

    class AuthenticationInfoCallbackHandler implements CallbackHandler {
        
        AuthenticationInfo authenticationInfo;
        
        AuthenticationInfoCallbackHandler(AuthenticationInfo authenticationInfo) {
            this.authenticationInfo = authenticationInfo;
        }
        
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof NameCallback) {
                    ((NameCallback) callbacks[i]).setName(authenticationInfo.getUserName());
                } else if (callbacks[i] instanceof PasswordCallback) {
                    ((PasswordCallback) callbacks[i]).setPassword(authenticationInfo.getPassword().toCharArray());
                }
            }
        }
        
    }

    @Override
    public boolean validateCredentials(AuthenticationInfo authenticationInfo) throws Exception {
        LoginContext loginContext = new LoginContext(loginContextName,new AuthenticationInfoCallbackHandler(authenticationInfo));
        loginContext.login();
        return true;
    }

}
