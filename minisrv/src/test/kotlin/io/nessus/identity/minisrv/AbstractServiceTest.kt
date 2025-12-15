package io.nessus.identity.minisrv

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.ktor.server.engine.*
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.NoopIssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService
import kotlinx.serialization.json.*
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class AbstractServiceTest {

    val log = KotlinLogging.logger {}
    val jsonPretty = Json { prettyPrint = true }

    lateinit var embeddedServer: EmbeddedServer<*, *>
    lateinit var issuerSvc: IssuerService
    lateinit var walletSvc: WalletService
    lateinit var verifierSvc: VerifierService
    lateinit var sessionStore: SessionStore

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
        embeddedServer.stop()
    }

    open fun createIssuerService(): IssuerService = NoopIssuerService()
    open fun createWalletService(): WalletService = WalletService.createNative()
    open fun createVerifierService(): VerifierService = VerifierService.createNative()
    open fun createSessionStore(): SessionStore = BasicSessionStore()

    open fun buildMiniServer(): MiniServer {
        issuerSvc = createIssuerService()
        walletSvc = createWalletService()
        verifierSvc = createVerifierService()
        sessionStore = createSessionStore()
        return MiniServerBuilder()
            .withIssuerService(issuerSvc)
            .withWalletService(walletSvc)
            .withVerifierService(verifierSvc)
            .withSessionsStore(sessionStore)
            .build()
    }
}
