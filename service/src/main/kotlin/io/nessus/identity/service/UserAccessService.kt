package io.nessus.identity.service

import org.keycloak.representations.idm.UserRepresentation

// UserAccessService ===================================================================================================

interface UserAccessService {

    /**
     * Get registered users
     */
    fun getUsers(): List<UserInfo>

    /**
     * Find a user by email
     */
    fun findUser(predicate: (UserInfo) -> Boolean): UserInfo?

    /**
     * Find a user by email
     */
    fun findUserByEmail(email: String): UserInfo?

    /**
     * Create a new user
     */
    fun createUser(
        firstName: String,
        lastName: String,
        email: String,
        username: String,
        password: String
    ): UserInfo

    /**
     * Delete new user
     */
    fun deleteUser(userId: String)

    data class UserInfo(
        val id: String,
        val did: String?,
        val firstName: String,
        val lastName: String,
        val email: String,
        val username: String,
    ) {
        companion object {
            fun fromUserRepresentation(usr: UserRepresentation) : UserInfo {
                val did = usr.attributes?.get("did")?.firstOrNull()
                return UserInfo(usr.id, did, usr.firstName, usr.lastName, usr.email, usr.username)
            }
        }
    }
}