/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth;

import java.net.URL;
import java.util.ArrayList;
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

    public static final String DEFAULT_REALMNAME="H2";

    Map<String, CredentialsValidator> realms = new HashMap<>();

    List<UserToRolesMapper> userToRolesMappers = new ArrayList<>();

    boolean allowUserRegistration;

    boolean persistUsers;

    boolean createMissingRoles;

    boolean skipDefaultInitialization;
    
    /**
     * Create the Authenticator with default configurations
     */
    public DefaultAuthenticator() {
    }
    
    /**
     * Create authenticator and optionally skip the default configuration. 
     * This option is useful when the authenticator is configured at code level 
     * @param skipDefaultInitialization = if true default initialization is skipped
     */
    public DefaultAuthenticator(boolean skipDefaultInitialization) {
        this.skipDefaultInitialization=skipDefaultInitialization;
    }
    
    /**
     * If set save users externals defined during the authentication.
     * @return
     */
    public boolean isPersistUsers() {
        return persistUsers;
    }

    public void setPersistUsers(boolean persistUsers) {
        this.persistUsers = persistUsers;
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

    public void setCreateMissingRoles(boolean createMissingRoles) {
        this.createMissingRoles = createMissingRoles;
    }

    public void addRealm(String name, CredentialsValidator credentialsValidator) {
        realms.put(name.toUpperCase(), credentialsValidator);
    }
    /**
     * UserToRoleMappers assign roles to authenticated users
     * @return current UserToRoleMappers active
     */
    public List<UserToRolesMapper> getUserToRolesMappers() {
        return userToRolesMappers;
    }

    public void setUserToRolesMappers(UserToRolesMapper... userToRolesMappers) {
        List<UserToRolesMapper> userToRolesMappersList = new ArrayList<>();
        for ( UserToRolesMapper current : userToRolesMappers) {
            userToRolesMappersList.add(current);
        }
        this.userToRolesMappers = userToRolesMappersList;
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
        if (skipDefaultInitialization) {
            return;
        }
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
        realms = new HashMap<>();
        CredentialsValidator jaasCredentialsValidator = new JaasCredentialsValidator();
        jaasCredentialsValidator.configure(new ConfigProperties());
        realms.put(DEFAULT_REALMNAME, jaasCredentialsValidator);
        UserToRolesMapper assignRealmNameRole = new AssignRealmNameRole();
        assignRealmNameRole.configure(new ConfigProperties());
        userToRolesMappers.add(assignRealmNameRole);
    }
    
    void configureFrom(H2AuthConfig config) throws Exception {
        allowUserRegistration = config.isAllowUserRegistration();
        createMissingRoles = config.isCreateMissingRoles();
        Map<String, CredentialsValidator> newRealms = new HashMap<>();
        for (RealmConfig currentRealmConfig : config.getRealms()) {
            String currentRealmName=currentRealmConfig.getName();
            if (currentRealmName==null) {
                throw new Exception("Missing realm name");
            }
            currentRealmName=currentRealmName.toUpperCase();
            CredentialsValidator currentValidator =null;
            try {
                currentValidator = (CredentialsValidator) Class
                    .forName(currentRealmConfig.getValidatorClass()).newInstance();
            } catch (Exception e) {
                throw new Exception("invalid validator class fo realm "+currentRealmName,e);
            }
            currentValidator.configure(new ConfigProperties(currentRealmConfig.getProperties()));
            if (newRealms.put(currentRealmConfig.getName().toUpperCase(), currentValidator) != null) {
                throw new Exception("Duplicate realm " + currentRealmConfig.getName());
            }
        }
        this.realms = newRealms;
        List<UserToRolesMapper> newUserToRolesMapper = new ArrayList<>();
        for (UserToRolesMapperConfig currentUserToRolesMapperConfig : config.getUserToRolesMappers()) {
            UserToRolesMapper currentUserToRolesMapper=null;
            try {
                currentUserToRolesMapper = (UserToRolesMapper) Class
                        .forName(currentUserToRolesMapperConfig.getClassName()).newInstance();
            }catch (Exception e) {
                throw new Exception("Invalid class in UserToRolesMapperConfig",e);
            }
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
        CredentialsValidator validator = realms.get(authenticationInfo.getRealm());
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
