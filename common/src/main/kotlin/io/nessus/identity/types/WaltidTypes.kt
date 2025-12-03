package io.nessus.identity.types

import id.walt.webwallet.db.models.WalletCredential
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlin.time.Instant

// Authentication --------------------------------------------------------------------------------------------------

enum class LoginType(val type: String) { EMAIL("email") }

data class LoginParams(val type: LoginType, val email: String, val password: String) {
    fun toAuthLoginRequest(): LoginRequest {
        return LoginRequest(type.type, email, password)
    }
}

data class RegisterUserParams(val type: LoginType, val name: String, val email: String, val password: String) {
    fun toAuthRegisterRequest(): RegisterUserRequest {
        return RegisterUserRequest(type.type, name, email, password)
    }
}

@Serializable
data class LoginRequest(
    val type: String,
    val email: String,
    val password: String
)

@Serializable
data class LoginResponse(
    val id: String,
    val username: String,
    val token: String
)

@Serializable
data class RegisterUserRequest(
    val type: String,
    val name: String,
    val email: String,
    val password: String
)

@Serializable
data class WaltIdUser(
    val id: String,
    val name: String,
    val email: String,
    @Serializable(with = TimeInstantSerializer::class)
    val createdOn: Instant
)

// Account ---------------------------------------------------------------------------------------------------------

@Serializable
data class WalletInfo(
    val id: String,
    val name: String,
    val createdOn: String,
    val addedOn: String,
    val permission: String
)

@Serializable
@Suppress("ArrayInDataClass")
data class ListWalletsResponse(
    val account: String,
    val wallets: Array<WalletInfo>
)

// Credentials ---------------------------------------------------------------------------------------------------------

@Serializable
@Suppress("ArrayInDataClass")
data class ListWalletCredentialsResponse(
    val credentials: Array<WalletCredential>
)

// Keys ----------------------------------------------------------------------------------------------------------------

@Serializable
data class KeyResponse(
    val algorithm: String,
    val cryptoProvider: String,
    val keyId: KeyId,
)

@Serializable
data class KeyId(
    val id: String,
)

// Keys ----------------------------------------------------------------------------------------------------------------

enum class KeyType(val algorithm: String) {
    ED25519("Ed25519"),
    SECP256R1("secp256r1");

    override fun toString(): String = algorithm
}

data class Key(val id: String, val algorithm: String)

@Serializable
data class DidInfo(
    val did: String,
    val alias: String,
    val document: String,
    val keyId: String,
    val createdOn: String,
    val default: Boolean
)

fun DidInfo.authenticationId(): String {
    val docJson = Json.parseToJsonElement(this.document).jsonObject
    val authId = (docJson["authentication"] as JsonArray).let { it[0].jsonPrimitive.content }
    return authId
}

fun DidInfo.publicKeyJwk(): JsonObject {
    val docJson = Json.parseToJsonElement(this.document).jsonObject
    val keyJwk = (docJson["verificationMethod"] as JsonArray)
        .map { it as JsonObject }
        .first { it["controller"]?.jsonPrimitive?.content == this.did }
        .getValue("publicKeyJwk").jsonObject
    return keyJwk
}

@Serializable
data class CreateDidKeyRequest(
    val alias: String = "",
    val keyId: String = "",
    val useJwkJcsPub: Boolean = true,
)

@Serializable
data class ErrorResponse(
    val exception: Boolean = false,
    val id: String = "",
    val status: String = "",
    val code: Int = 0,
    val message: String,
)

