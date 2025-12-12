package io.nessus.identity.minisrv

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.ktor.server.engine.*
import io.nessus.identity.LoginContext
import io.nessus.identity.LoginContext.Companion.USER_ROLE_ATTACHMENT_KEY
import io.nessus.identity.LoginContext.Companion.login
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.NativeIssuerService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.*
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}
    val jsonPretty = Json { prettyPrint = true }

    lateinit var embeddedServer: EmbeddedServer<*, *>
    lateinit var issuerSvc: IssuerService
    lateinit var walletSvc: WalletService

    lateinit var alice: LoginContext

    @BeforeAll
    fun beforeAll() {
        runBlocking {
            startMiniServer()
        }
    }

    @AfterAll
    fun afterAll() {
        stopMiniServer()
    }

    fun startMiniServer() {
        val miniServer = buildMiniServer()
        issuerSvc = miniServer.issuerSvc
        walletSvc = miniServer.walletSvc
        embeddedServer = miniServer.create()
        embeddedServer.start(wait = false)
    }

    fun stopMiniServer() {
        embeddedServer.stop(3000, 5000)
    }

    @BeforeEach
    fun setUp() {
        runBlocking {
            if (issuerSvc is NativeIssuerService) {
                // [TODO] can we really reuse this context
                val issuerContext = (issuerSvc as NativeIssuerService).adminContext
                issuerContext.putAttachment(USER_ROLE_ATTACHMENT_KEY, UserRole.Issuer)
                SessionsStore.putLoginContext(issuerContext)
            }
            alice = login(Alice).withDidInfo()
            alice.putAttachment(USER_ROLE_ATTACHMENT_KEY, UserRole.Holder)
            SessionsStore.putLoginContext(alice)
        }
    }

    abstract fun createIssuerService(): IssuerService

    open fun buildMiniServer(): MiniServer {
        val issuerSvc = createIssuerService()
        return MiniServerBuilder()
            .withIssuerService(issuerSvc)
            .build()
    }
}
