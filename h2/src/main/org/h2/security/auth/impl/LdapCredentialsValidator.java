/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth.impl;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.h2.security.auth.AuthenticationInfo;
import org.h2.security.auth.ConfigProperties;
import org.h2.security.auth.spi.CredentialsValidator;

/**
 * Validate credentials by performing an LDAP bind
 * 
 * configuration parameters:
 *    bindDnPattern = bind dn pattern with %u istead of username (example: uid=%u,ou=users,dc=example,dc=com)
 *    host = ldap host
 *    port (optional) = ldap port (by default 389 for unsecure, 636 for secure)
 *    secure (optional) = use ssl (default true)
 */
public class LdapCredentialsValidator implements CredentialsValidator {

    String bindDnPattern;
    String host;
    int port;
    boolean secure;
    String url;

    @Override
    public void configure(ConfigProperties configProperties) {
        bindDnPattern = configProperties.getStringValue("bindDnPattern");
        host = configProperties.getStringValue("host");
        secure = configProperties.getBooleanValue("secure", true);
        port = configProperties.getIntValue("port", secure ? 636 : 389);
        url = "ldap" + (secure ? "s" : "") + "://" + host + ":" + port;
    }

    @Override
    public boolean validateCredentials(AuthenticationInfo authenticationInfo) throws Exception {
        DirContext dirContext = null;
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, url);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, bindDnPattern.replace("%u", authenticationInfo.getUserName()));
            env.put(Context.SECURITY_CREDENTIALS, authenticationInfo.getPassword());
            dirContext = new InitialDirContext(env);
            return true;
        } finally {
            if (dirContext != null) {
                dirContext.close();
            }
        }

    }

}
