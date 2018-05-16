package org.h2.security.auth;

import org.h2.engine.Database;
import org.h2.engine.User;

public class UserBuilder {

    /**
     * build the database user starting from authentication informations
     * @param authenticationInfo = authentication info
     * @param database = target database
     * @param persistent = true if the user will be persisted in the database
     * @return user bean
     */
    public static User buildUser(AuthenticationInfo authenticationInfo, Database database, boolean persistent) {
        User user = new User(database, persistent ? database.allocateObjectId() : -1, authenticationInfo.getFullyQualifiedName(), false);
        user.setUserPasswordHash(new byte[] { -1 });
        user.setTemporary(persistent == false);
        return user;
    }
}
