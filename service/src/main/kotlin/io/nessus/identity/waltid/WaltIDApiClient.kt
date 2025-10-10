package io.nessus.identity.waltid

import id.walt.webwallet.db.models.WalletCredential
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.HttpHeaders.Authorization
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.http
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class APIException(val id: String, val code: Int, val status: String, message: String) : RuntimeException(message) {

    constructor(err: ErrorResponse) : this(err.id, err.code, err.status, err.message)

    override fun toString(): String {
        return if (id.isNotEmpty() || code > 0 || status.isNotEmpty()) {
            "APIException[id=$id, code=$code, status=$status] $message"
        } else {
            message!!
        }
    }
}

@Suppress("UNCHECKED_CAST")
suspend inline fun <reified T> handleResponse(res: HttpResponse): T {
    val body = res.bodyAsText()
    val json = Json { ignoreUnknownKeys = true }
    if (res.status.value in 200..<300) {
        val resVal = if (T::class == HttpResponse::class) {
            res as T
        } else if (T::class == String::class) {
            body as T
        } else if (T::class == Boolean::class) {
            when {
                body.isEmpty() -> true as T
                else -> body.toBoolean() as T
            }
        } else {
            json.decodeFromString<T>(body)
        }
        return resVal
    }
    val err = json.decodeFromString<ErrorResponse>(body)
    throw APIException(err)
}

// WaltIDApiClient =====================================================================================================

class WaltIDApiClient(val baseUrl: String) {

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun authLogin(req: LoginRequest): LoginResponse {
        val res = http.post("$baseUrl/wallet-api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(req)
        }
        val loginResponse = handleResponse<LoginResponse>(res)
        return loginResponse
    }

    suspend fun authLogout(): Boolean {
        val res = http.post("$baseUrl/wallet-api/auth/logout") {
            contentType(ContentType.Application.Json)
        }
        handleResponse<HttpResponse>(res)
        return true
    }

    suspend fun authRegister(req: RegisterUserRequest): String {
        val res = http.post("$baseUrl/wallet-api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(req)
        }
        return handleResponse<String>(res)
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun accountWallets(ctx: LoginContext): ListWalletsResponse {
        val res = http.get("$baseUrl/wallet-api/wallet/accounts/wallets") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
        }
        return handleResponse<ListWalletsResponse>(res)
    }

    // Credentials -----------------------------------------------------------------------------------------------------

    suspend fun credentials(ctx: LoginContext): Array<WalletCredential> {
        val res = http.get("$baseUrl/wallet-api/wallet/${ctx.walletId}/credentials") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
        }
        return handleResponse<Array<WalletCredential>>(res)
    }

    suspend fun deleteCredential(ctx: LoginContext, vcId: String): Boolean {
        val encId = vcId.encodeURLPath()
        val res = http.delete("$baseUrl/wallet-api/wallet/${ctx.walletId}/credentials/$encId?permanent=true") {
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
        }
        return handleResponse<Boolean>(res)
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun export(ctx: LoginContext, kid: String): String {
        val encKid = kid.encodeURLPath()
        val res = http.get("$baseUrl/wallet-api/wallet/${ctx.walletId}/keys/$encKid/export") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
        }
        return handleResponse<String>(res)
    }

    suspend fun keys(ctx: LoginContext): Array<KeyResponse> {
        val res = http.get("$baseUrl/wallet-api/wallet/${ctx.walletId}/keys") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
        }
        return handleResponse<Array<KeyResponse>>(res)
    }

    suspend fun keysGenerate(ctx: LoginContext, keyType: KeyType): String {
        val keyConfig = Json.encodeToString(mapOf("keyType" to keyType.algorithm))
        val res = http.post("$baseUrl/wallet-api/wallet/${ctx.walletId}/keys/generate") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
            setBody(keyConfig)
        }
        return handleResponse<String>(res)
    }

    suspend fun keysSign(ctx: LoginContext, alias: String, message: String): String {
        val encAlias = alias.encodeURLPath()
        val res = http.post("$baseUrl/wallet-api/wallet/${ctx.walletId}/keys/$encAlias/sign") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
            setBody(message)
        }
        return handleResponse<String>(res)
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    suspend fun did(ctx: LoginContext, did: String): JsonObject {
        val res = http.get("$baseUrl/wallet-api/wallet/${ctx.walletId}/dids/${did}") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
        }
        return handleResponse<JsonObject>(res)
    }

    suspend fun dids(ctx: LoginContext): Array<DidInfo> {
        val res = http.get("$baseUrl/wallet-api/wallet/${ctx.walletId}/dids") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
        }
        return handleResponse<Array<DidInfo>>(res)
    }

    suspend fun didsCreateDidKey(ctx: LoginContext, req: CreateDidKeyRequest): String {
        val res = http.post("$baseUrl/wallet-api/wallet/${ctx.walletId}/dids/create/key") {
            contentType(ContentType.Application.Json)
            headers {
                append(Authorization, "Bearer ${ctx.authToken}")
            }
            url {
                if (req.keyId.isNotEmpty()) {
                    parameters.append("keyId", req.keyId)
                }
                if (req.alias.isNotEmpty()) {
                    parameters.append("alias", req.alias)
                }
                parameters.append("useJwkJcsPub", "${req.useJwkJcsPub}")
            }
        }
        return handleResponse(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}

// Authentication --------------------------------------------------------------------------------------------------

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

