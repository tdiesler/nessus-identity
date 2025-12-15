package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.LoginContext
import io.nessus.identity.config.User

abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}

    companion object {
        val sessions = mutableMapOf<String, LoginContext>()
    }

    suspend fun login(user: User): LoginContext {
        val ctx = sessions[user.email] ?: run {
            LoginContext.login(user).also {
                sessions[user.email] = it
            }
        }
        return ctx
    }
}