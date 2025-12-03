package io.nessus.identity.types

import org.keycloak.representations.idm.UserRepresentation

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
