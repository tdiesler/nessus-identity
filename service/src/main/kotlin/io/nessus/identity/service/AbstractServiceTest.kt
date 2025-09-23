package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.waltid.APIException
import io.nessus.identity.waltid.KeyType
import io.nessus.identity.waltid.User
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletSvc
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Paths

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

    fun loadResourceAsString(path: String): String {
        val resourceUrl = AbstractServiceTest::class.java.classLoader.getResource(path)
            ?: throw IllegalArgumentException("Resource not found: $path")
        return Files.readString(Paths.get(resourceUrl.toURI()))
    }
}