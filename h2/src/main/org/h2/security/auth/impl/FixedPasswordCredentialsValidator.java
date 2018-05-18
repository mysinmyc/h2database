/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth.impl;

import org.h2.api.CredentialsValidator;
import org.h2.security.SHA256;
import org.h2.security.auth.AuthenticationException;
import org.h2.security.auth.AuthenticationInfo;
import org.h2.security.auth.ConfigProperties;
import org.h2.util.StringUtils;
import org.h2.util.Utils;

/**
 * This credentials validator matches the user password with the configured 
 * Usage should be limited to test purposes
 *
 */
public class FixedPasswordCredentialsValidator implements CredentialsValidator {

    String password;
    byte[] salt;
    byte[] hashWithSalt;

    @Override
    public boolean validateCredentials(AuthenticationInfo authenticationInfo) throws AuthenticationException {
        if (password!=null) {
            return password.equals(authenticationInfo.getPassword());
        }
        return Utils.compareSecure(hashWithSalt,SHA256.getHashWithSalt(authenticationInfo.getPassword().getBytes(), salt));
    }

    @Override
    public void configure(ConfigProperties configProperties) {
        password=configProperties.getStringValue("password",null);
        if (password==null) {
            byte[] hash = StringUtils.convertHexToBytes(configProperties.getStringValue("hash"));
            salt = StringUtils.convertHexToBytes(configProperties.getStringValue("salt"));
            hashWithSalt = SHA256.getHashWithSalt(hash, salt);
        }
    }

}
