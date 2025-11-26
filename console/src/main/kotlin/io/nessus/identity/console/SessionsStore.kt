package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.application.*
import io.ktor.server.sessions.*
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.urlDecode
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.LoginParams
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

object SessionsStore {

    val log = KotlinLogging.logger {}

    // Registry that allows us to restore a LoginContext from targetId
    private val loginContexts = mutableSetOf<LoginContext>()

    fun cookieName(role: UserRole) = "${role.name}Cookie"

    suspend fun createLoginContext(call: ApplicationCall, role: UserRole, params: LoginParams): LoginContext {
        val ctx = LoginContext.login(params).withUserRole(role).withWalletInfo()
        val wid = ctx.walletId
        val did = ctx.maybeDidInfo?.did
        when (role) {
            UserRole.Holder -> call.sessions.set(HolderCookie(wid, did))
            UserRole.Issuer -> call.sessions.set(IssuerCookie(wid, did))
            UserRole.Verifier -> call.sessions.set(VerifierCookie(wid, did))
        }
        loginContexts.add(ctx)
        return ctx
    }

    /**
     * Finds a LoginContext from the wallet's targetId
     */
    fun findLoginContext(call: ApplicationCall, targetId: String): LoginContext? {
        val ctx = loginContexts.firstOrNull { it.targetId == targetId }
        return ctx
    }

    /**
     * Finds a LoginContext from session cookie
     */
    fun findLoginContext(call: ApplicationCall, role: UserRole): LoginContext? {
        val cookie = getCookieFromSession(call, role)
        val ctx = cookie?.let {
            findLoginContext(call, it.targetId)
        }
        return ctx
    }

    fun requireLoginContext(call: ApplicationCall, role: UserRole): LoginContext {
        return requireNotNull(findLoginContext(call, role)) { "No ${role.name} LoginContext" }
    }

    fun logout(call: ApplicationCall, targetId: String) {
        findLoginContext(call, targetId)?.also {
            call.sessions.clear(cookieName(it.userRole))
            loginContexts.removeIf { it.targetId == targetId }
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

    private fun getCookieFromSession(call: ApplicationCall, targetId: String): BaseCookie? {
        val cookie = call.request.cookies.rawCookies.map { (_, v) ->
            Json.decodeFromString<BaseCookie>(urlDecode(v))
        }.firstOrNull { it.targetId == targetId }
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