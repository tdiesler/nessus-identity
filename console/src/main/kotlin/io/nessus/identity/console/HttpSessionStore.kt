package io.nessus.identity.console

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.sessions.*
import io.nessus.identity.LoginContext
import io.nessus.identity.minisrv.BasicSessionStore
import io.nessus.identity.types.LoginParams
import io.nessus.identity.types.UserRole
import io.nessus.identity.utils.urlDecode
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

object HttpSessionStore : BasicSessionStore() {

    fun cookieName(role: UserRole) = "${role.name}Cookie"

    suspend fun createLoginContext(call: ApplicationCall, role: UserRole, params: LoginParams): LoginContext {
        val ctx = super.login(role, params)
        val wid = ctx.walletId
        val did = ctx.maybeDidInfo?.did
        when (role) {
            UserRole.Holder -> call.sessions.set(HolderCookie(wid, did))
            UserRole.Issuer -> call.sessions.set(IssuerCookie(wid, did))
            UserRole.Verifier -> call.sessions.set(VerifierCookie(wid, did))
        }
        return ctx
    }

    /**
     * Finds a LoginContext from session cookie
     */
    fun findLoginContext(call: ApplicationCall, role: UserRole): LoginContext? {
        val cookie = getCookieFromSession(call, role)
        val authToken = call.request.header(HttpHeaders.Authorization)
        val targetId = call.parameters["targetId"]
        val ctx = cookie?.let { findLoginContext(it.targetId) }
            ?: authToken?.let { findLoginContextByAuthToken(it) }
            ?: targetId?.let { findLoginContextByTxCode(it) }
            ?: targetId?.let { findLoginContext(targetId) } // [TODO] Remove this insecure lookup used vp flow
        return ctx
    }

    fun requireLoginContext(call: ApplicationCall, role: UserRole): LoginContext {
        return requireNotNull(findLoginContext(call, role)) { "No ${role.name} LoginContext" }
    }

    fun logout(call: ApplicationCall, role: UserRole) {
        findLoginContext(call, role)?.also {
            call.sessions.clear(cookieName(it.userRole))
            logout(it.targetId)
        }
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun getCookieFromSession(call: ApplicationCall, role: UserRole): BaseCookie? {
        val cookie = call.request.cookies.rawCookies
            .filter { (k, _) -> k == cookieName(role) }
            .map { (_, v) ->
                when (role) {
                    UserRole.Holder -> Json.decodeFromString<HolderCookie>(urlDecode(v))
                    UserRole.Issuer -> Json.decodeFromString<IssuerCookie>(urlDecode(v))
                    UserRole.Verifier -> Json.decodeFromString<VerifierCookie>(urlDecode(v))
                }
            }
            .onEach { log.info { "Found role cookie: [role=${it.role}, tid=${it.targetId}]" } }
            .firstOrNull()
        return cookie
    }
}

@Serializable(with = CookieSerializer::class)
sealed class BaseCookie() {
    abstract val role: UserRole
    abstract val wid: String
    abstract val did: String?

    val targetId
        get() = LoginContext.getTargetId(wid, did ?: "")
}

@Serializable
data class HolderCookie(
    override val wid: String,
    override val did: String? = null
) : BaseCookie() {
    override val role: UserRole = UserRole.Holder
}

@Serializable
data class IssuerCookie(
    override val wid: String,
    override val did: String? = null
) : BaseCookie() {
    override val role: UserRole = UserRole.Issuer
}

@Serializable
data class VerifierCookie(
    override val wid: String,
    override val did: String? = null
) : BaseCookie() {
    override val role: UserRole = UserRole.Verifier
}

object CookieSerializer : JsonContentPolymorphicSerializer<BaseCookie>(BaseCookie::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<BaseCookie> {
        return when (element.jsonObject["role"]?.jsonPrimitive?.content) {
            "Holder" -> HolderCookie.serializer()
            "Issuer" -> IssuerCookie.serializer()
            "Verifier" -> VerifierCookie.serializer()
            else -> throw SerializationException("Unknown role in cookie: $element")
        }
    }
}