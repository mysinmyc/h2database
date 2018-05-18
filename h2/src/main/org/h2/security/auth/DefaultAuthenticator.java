/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.JAXB;

import org.h2.api.Authenticator;
import org.h2.api.CredentialsValidator;
import org.h2.api.UserToRolesMapper;
import org.h2.engine.Database;
import org.h2.engine.Right;
import org.h2.engine.Role;
import org.h2.engine.User;
import org.h2.engine.UserBuilder;
import org.h2.security.auth.impl.AssignRealmNameRole;
import org.h2.security.auth.impl.JaasCredentialsValidator;

/**
 * Default implementation of authenticator.
 * Credentials (typically user id and password) are validated by CredentialsValidators (one per realm).
 * Rights on the database can be managed trough UserToRolesMapper.
 *
 */
public class DefaultAuthenticator implements Authenticator {

    Map<String, CredentialsValidator> validators = new HashMap<>();

    List<UserToRolesMapper> userToRolesMappers = new ArrayList<>();

    boolean allowUserRegistration;

    boolean persistUsers;

    /**
     * If set save users externals defined during the authentication.
     * @return
     */
    public boolean isPersistUsers() {
        return persistUsers;
    }

    /**
     * If set create external users in the database if not present.
     * @return
     */
    public boolean isAllowUserRegistration() {
        return allowUserRegistration;
    }

    public void setAllowUserRegistration(boolean allowUserRegistration) {
        this.allowUserRegistration = allowUserRegistration;
    }

    /**
     * When set create roles not found in the database. If not set
     * roles not found in the database are silently skipped
     * @return
     */
    public boolean isCreateMissingRoles() {
        return createMissingRoles;
    }

    boolean createMissingRoles;

    public DefaultAuthenticator() {
    }

    /**
     * Initializes the authenticator
     * 
     * order of initialization is
     * 1. Check h2auth.configurationFile system property.
     * 2. Check h2auth.xml in the classpath
     * 3. Perform the default initialization 
     * 
     */
    public void init() throws AuthConfigException{
        URL h2AuthenticatorConfigurationUrl=null;
        try {
            String configFile = System.getProperty("h2auth.configurationFile", null);
            if (configFile != null) {
                h2AuthenticatorConfigurationUrl = new URL(configFile);
            }
            if (h2AuthenticatorConfigurationUrl == null) {
                h2AuthenticatorConfigurationUrl = Thread.currentThread().
                    getContextClassLoader().getResource("h2auth.xml");
            } 
            if (h2AuthenticatorConfigurationUrl ==null) {
                defaultConfiguration();
            } else {
                H2AuthConfig config = JAXB.unmarshal(h2AuthenticatorConfigurationUrl, H2AuthConfig.class);
                configureFrom(config);
            }
        } catch (Exception e) {
            throw new AuthConfigException("Failed to configure authentication from "+h2AuthenticatorConfigurationUrl,e);
        }
    }

    void defaultConfiguration() {
        createMissingRoles=false;
        allowUserRegistration=true;
        validators = new HashMap<>();
        CredentialsValidator jaasCredentialsValidator = new JaasCredentialsValidator();
        jaasCredentialsValidator.configure(new ConfigProperties());
        validators.put("h2", jaasCredentialsValidator);
        UserToRolesMapper assignRealmNameRole = new AssignRealmNameRole();
        assignRealmNameRole.configure(new ConfigProperties());
        userToRolesMappers.add(assignRealmNameRole);
    }
    
    void configureFrom(H2AuthConfig config) throws Exception {
        allowUserRegistration = config.isAllowUserRegistration();
        createMissingRoles = config.isCreateMissingRoles();
        Map<String, CredentialsValidator> newValidators = new HashMap<>();
        for (CredentialsValidatorConfig currentValidatorConfig : config.getValidators()) {
            CredentialsValidator currentValidator = (CredentialsValidator) Class
                    .forName(currentValidatorConfig.getClassName()).newInstance();
            currentValidator.configure(new ConfigProperties(currentValidatorConfig.getProperties()));
            if (newValidators.put(currentValidatorConfig.getRealmName(), currentValidator) != null) {
                throw new Exception("Duplicate realm " + currentValidatorConfig.getRealmName());
            }
        }
        this.validators = newValidators;
        List<UserToRolesMapper> newUserToRolesMapper = new ArrayList<>();
        for (UserToRolesMapperConfig currentUserToRolesMapperConfig : config.getUserToRolesMappers()) {
            UserToRolesMapper currentUserToRolesMapper = (UserToRolesMapper) Class
                    .forName(currentUserToRolesMapperConfig.getClassName()).newInstance();
            currentUserToRolesMapper.configure(new ConfigProperties(currentUserToRolesMapperConfig.getProperties()));
            newUserToRolesMapper.add(currentUserToRolesMapper);
        }
        this.userToRolesMappers = newUserToRolesMapper;
    }

    void updateRoles(AuthenticationInfo authenticationInfo, User user, Database database)
            throws AuthenticationException {
        Set<String> roles = new HashSet<>();
        for (UserToRolesMapper currentUserToRolesMapper : userToRolesMappers) {
            Collection<String> currentRoles = currentUserToRolesMapper.mapUserToRoles(authenticationInfo);
            if (currentRoles != null && currentRoles.isEmpty() == false) {
                roles.addAll(currentRoles);
            }
        }
        for (String currentRoleName : roles) {
            if (currentRoleName == null || currentRoleName.isEmpty()) {
                continue;
            }
            Role currentRole = database.findRole(currentRoleName);
            if (currentRole == null && isCreateMissingRoles()) {
                synchronized (database.getSystemSession()) {
                    currentRole = new Role(database, database.allocateObjectId(), currentRoleName, false);
                    database.addDatabaseObject(database.getSystemSession(), currentRole);
                }
            }
            if (currentRole == null) {
                continue;
            }
            if (user.getRightForRole(currentRole) == null) {
                // NON PERSISTENT
                Right currentRight = new Right(database, -1, user, currentRole);
                currentRight.setTemporary(true);
                user.grantRole(currentRole, currentRight);
            }
        }
    }

    @Override
    public final User authenticate(AuthenticationInfo authenticationInfo, Database database)
            throws AuthenticationException {
        String userName = authenticationInfo.getFullyQualifiedName();
        User user = database.findUser(userName);
        if (user == null && isAllowUserRegistration() == false) {
            throw new AuthenticationException("User " + userName + " not found in db");
        }
        CredentialsValidator validator = validators.get(authenticationInfo.getRealm());
        if (validator == null) {
            throw new AuthenticationException("realm " + authenticationInfo.getRealm() + " not configured");
        }
        try {
            if (validator.validateCredentials(authenticationInfo) == false) {
                return null;
            }
        } catch (Exception e) {
            throw new AuthenticationException(e);
        }
        if (user == null) {
            synchronized (database.getSystemSession()) {
               user = UserBuilder.buildUser(authenticationInfo, database,isPersistUsers());
               database.addDatabaseObject(database.getSystemSession(), user);
            }
        }
        user.revokeTemporaryRightsOnRoles();
        updateRoles(authenticationInfo, user, database);
        synchronized (database.getSystemSession()) {
            database.getSystemSession().commit(false);
        }
        return user;
    }
}
