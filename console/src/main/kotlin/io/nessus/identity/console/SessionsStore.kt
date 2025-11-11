package io.nessus.identity.console

import io.ktor.server.routing.*
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

    // Registry that allows us to restore a LoginContext from subjectId
    val loginContexts = mutableMapOf<String, LoginContext>()

    fun cookieName(role: UserRole) = "${role.name}Cookie"

    suspend fun createLoginContext(call: RoutingCall, role: UserRole, params: LoginParams): LoginContext {
        val ctx = LoginContext.login(params).withUserRole(role).withWalletInfo()
        val wid = ctx.walletId
        val did = ctx.maybeDidInfo?.did
        when (role) {
            UserRole.Holder -> call.sessions.set(HolderCookie(wid, did))
            UserRole.Verifier -> call.sessions.set(VerifierCookie(wid, did))
        }
        loginContexts[ctx.targetId] = ctx
        return ctx
    }

    fun findLoginContext(call: RoutingCall, role: UserRole, targetId: String? = null): LoginContext? {
        val ctx = getRoleCookieFromSession(call, role)
            ?.let { LoginContext.getTargetId(it.wid, it.did ?: "") }
            ?.takeIf { tid -> tid == targetId || targetId == null }
            ?.let { tid -> loginContexts[tid] }
        return ctx
    }

    fun logout(call: RoutingCall, role: UserRole) {
        findLoginContext(call, role)?.also {
            call.sessions.clear(cookieName(role))
            loginContexts.remove(it.targetId)
        }
    }

    fun requireLoginContext(call: RoutingCall, role: UserRole, targetId: String? = null): LoginContext {
        val ctx = findLoginContext(call, role, targetId) ?: error("No ${role.name} LoginContext")
        return ctx
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun getRoleCookieFromSession(call: RoutingCall, role: UserRole): BaseCookie? {
        val roleCookie = call.request.cookies.rawCookies
            .filter { (k, _) -> k == cookieName(role) }
            .map { (_, v) ->
                when (role) {
                    UserRole.Holder -> Json.decodeFromString<HolderCookie>(urlDecode(v))
                    UserRole.Verifier -> Json.decodeFromString<VerifierCookie>(urlDecode(v))
                }
            }.firstOrNull()
        return roleCookie
    }
}

@Serializable(with = CookieSerializer::class)
sealed class BaseCookie {
    abstract val role: UserRole
    abstract val wid: String
    abstract val did: String?
}

@Serializable
data class HolderCookie(
    override val wid: String,
    override val did: String? = null
) : BaseCookie() {
    override val role: UserRole = UserRole.Holder
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
            "Verifier" -> VerifierCookie.serializer()
            else -> throw SerializationException("Unknown role in cookie: $element")
        }
    }
}