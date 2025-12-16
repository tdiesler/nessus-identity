package io.nessus.identity.minisrv

import io.nessus.identity.LoginContext
import io.nessus.identity.config.User
import io.nessus.identity.types.LoginParams
import io.nessus.identity.types.UserRole

interface SessionStore {

    /**
     * Create a LoginContext for the given user and role
     */
    suspend fun login(role: UserRole, user: User): LoginContext

    /**
     * Create a LoginContext for the given login params and role
     */
    suspend fun login(role: UserRole, params: LoginParams): LoginContext

    /**
     * Find a LoginContext for the given targetId
     */
    fun findLoginContext(targetId: String): LoginContext?

    /**
     * Find a LoginContext by access token
     */
    fun findLoginContextByAuthToken(authToken: String): LoginContext?

    /**
     * Find a LoginContext by tx code
     */
    fun findLoginContextByTxCode(txCode: String): LoginContext?

    /**
     * Find a LoginContext for the given user
     */
    fun findLoginContextByUser(user: User): LoginContext?

    /**
     * Require a LoginContext for the given targetId
     */
    fun requireLoginContext(targetId: String): LoginContext

    /**
     * Remove the LoginContext for the given targetId
     */
    fun logout(targetId: String)
}