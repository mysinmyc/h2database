/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Describe configuration of H2 authentication
 */
@XmlRootElement(name = "h2Auth")
@XmlAccessorType(XmlAccessType.FIELD)
public class H2AuthConfig {

    @XmlAttribute
    boolean allowUserRegistration=true;

    public boolean isAllowUserRegistration() {
        return allowUserRegistration;
    }

    public void setAllowUserRegistration(boolean allowUserRegistration) {
        this.allowUserRegistration = allowUserRegistration;
    }
    
    @XmlAttribute
    boolean createMissingRoles=true;

    public boolean isCreateMissingRoles() {
        return createMissingRoles;
    }

    public void setCreateMissingRoles(boolean createMissingRoles) {
        this.createMissingRoles = createMissingRoles;
    }

    @XmlElement(name = "validator")
    List<CredentialsValidatorConfig> validators;

    public List<CredentialsValidatorConfig> getValidators() {
        if (validators == null) {
            validators = new ArrayList<>();
        }
        return validators;
    }

    public void setValidators(List<CredentialsValidatorConfig> validators) {
        this.validators = validators;
    }

    @XmlElement(name = "userToRolesMapper")
    List<UserToRolesMapperConfig> userToRolesMappers;

    public List<UserToRolesMapperConfig> getUserToRolesMappers() {
        if (userToRolesMappers == null) {
            userToRolesMappers = new ArrayList<>();
        }
        return userToRolesMappers;
    }

    public void setUserToRolesMappers(List<UserToRolesMapperConfig> userToRolesMappers) {
        this.userToRolesMappers = userToRolesMappers;
    }
}
