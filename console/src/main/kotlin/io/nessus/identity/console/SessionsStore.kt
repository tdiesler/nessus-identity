package io.nessus.identity.console

import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.LoginParams
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

object SessionsStore {

    // Registry that allows us to restore a LoginContext from subjectId
    private val sessionStore = mutableMapOf<String, LoginContext>()

    fun cookieName(role: UserRole) = "${role.name}Cookie"

    fun requireLoginContext(call: RoutingCall, role: UserRole): LoginContext {
        val ctx = findLoginContext(call, role) ?: error("No ${role.name} LoginContext")
        return ctx
    }

    suspend fun newLoginContext(call: RoutingCall, role: UserRole, params: LoginParams): LoginContext {
        val ctx = LoginContext.login(params).withUserRole(role).withWalletInfo()
        val wid = ctx.walletId
        val did = ctx.maybeDidInfo?.did
        when (role) {
            UserRole.Issuer -> call.sessions.set(IssuerCookie(wid, did))
            UserRole.Holder -> call.sessions.set(HolderCookie(wid, did))
            UserRole.Verifier -> call.sessions.set(VerifierCookie(wid, did))
        }
        sessionStore[ctx.targetId] = ctx
        return ctx
    }

    fun findLoginContext(call: RoutingCall, role: UserRole): LoginContext? {
        val cookie = getCookieDataFromSession(call, role)
        val ctx = cookie?.let {
            findLoginContext(it.wid, it.did ?: "")
        }
        if (ctx != null && ctx.userRole != role) error("Expected role '$role', was: ${ctx.userRole}")
        return ctx
    }

    fun findLoginContext(wid: String, did: String): LoginContext? {
        val targetId = LoginContext.getTargetId(wid, did)
        return sessionStore[targetId]
    }

    fun logout(call: RoutingCall, role: UserRole) {
        findLoginContext(call, role)?.also { ctx ->
            call.sessions.clear(cookieName(role))
        }
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun getCookieDataFromSession(call: RoutingCall, role: UserRole): BaseCookie? {
        val dat = call.sessions.get(cookieName(role))
        return dat as? BaseCookie
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
        return when (element.jsonObject["role"]?.jsonPrimitive?.content?.lowercase()) {
            "issuer" -> IssuerCookie.serializer()
            "holder" -> HolderCookie.serializer()
            "verifier" -> VerifierCookie.serializer()
            else -> throw SerializationException("Unknown role in cookie: $element")
        }
    }
}