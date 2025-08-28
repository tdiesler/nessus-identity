package io.nessus.identity.waltid

import com.nimbusds.jwt.SignedJWT
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.webwallet.db.models.WalletCredential
import id.walt.webwallet.service.credentials.CredentialsService
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.extend.toW3CCredentialJwt
import io.nessus.identity.service.AttachmentKeys.AUTH_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.WALLET_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.CredentialMatcher
import io.nessus.identity.service.LoginContext
import kotlinx.datetime.Clock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.jetbrains.exposed.sql.Database
import javax.sql.DataSource
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class WaltIDWalletService {

    val log = KotlinLogging.logger {}
    val api: WaltIDApiClient

    val dataSource: Lazy<DataSource> = lazy {
        val dbcfg = ConfigProvider.requireDatabaseConfig()
        log.info { "Database: ${dbcfg.jdbcUrl}" }
        HikariDataSource(HikariConfig().apply {
            jdbcUrl = dbcfg.jdbcUrl
            username = dbcfg.username
            password = dbcfg.password
            driverClassName = "org.postgresql.Driver"
            transactionIsolation = "TRANSACTION_SERIALIZABLE"
            maximumPoolSize = 10
            isAutoCommit = false
        })
    }

    constructor(apiUrl: String) {
        log.info { "WalletService: $apiUrl" }
        api = WaltIDApiClient(apiUrl)
    }

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun registerUser(params: RegisterUserParams): String {
        return api.authRegister(params.toAuthRegisterRequest()).trim()
    }

    suspend fun login(params: LoginParams): LoginContext {
        val res = api.authLogin(params.toAuthLoginRequest())
        val ctx = LoginContext().also {
            it.putAttachment(AUTH_TOKEN_ATTACHMENT_KEY, res.token)
        }
        return ctx
    }

    suspend fun loginWithWallet(params: LoginParams): LoginContext {
        val ctx = login(params).also {
            val wi = listWallets(it).first()
            it.putAttachment(WALLET_INFO_ATTACHMENT_KEY, wi)
        }
        return ctx
    }

    suspend fun logout(): Boolean {
        return api.authLogout()
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun findWallet(ctx: LoginContext, predicate: suspend (WalletInfo) -> Boolean): WalletInfo? {
        return api.accountWallets(ctx).wallets.firstOrNull { predicate(it) }
    }

    suspend fun findWalletByDid(ctx: LoginContext, did: String): WalletInfo? {
        return findWallet(ctx) { w -> listDids(ctx).any { it.did == did } }
    }

    suspend fun findWalletById(ctx: LoginContext, id: String): WalletInfo? {
        return findWallet(ctx) { w -> w.id == id }
    }

    suspend fun listWallets(ctx: LoginContext): List<WalletInfo> {
        val res = api.accountWallets(ctx)
        return res.wallets.toList()
    }

    // Credentials -----------------------------------------------------------------------------------------------------

    @OptIn(ExperimentalUuidApi::class)
    fun addCredential(walletId: String, format: CredentialFormat, credJwt: SignedJWT): String {

        if (format != CredentialFormat.jwt_vc)
            throw IllegalStateException("Unsupported credential format: $format")

        val credId = getCredentialId(credJwt)
        val walletUid = Uuid.Companion.parse(walletId)
        val document = credJwt.serialize()

        val walletCredential = WalletCredential(
            id = credId,
            format = format,
            wallet = walletUid,
            document = document,
            addedOn = Clock.System.now(),
            disclosures = null,
            deletedOn = null,
        )

        withConnection {
            log.info { "Adding WalletCredential: ${Json.encodeToString(walletCredential)}" }
            CredentialsService().add(walletUid, walletCredential)
            log.info { "Added WalletCredential: $credId" }
        }
        return credId
    }

    suspend fun listCredentials(ctx: LoginContext): List<WalletCredential> {
        val res = api.credentials(ctx)
        return res.toList()
    }

    suspend fun findCredentials(ctx: LoginContext, predicate: suspend (WalletCredential) -> Boolean): List<WalletCredential> {
        val res = api.credentials(ctx).filter { predicate(it) }
        return res.toList()
    }

    suspend fun findCredentialsByType(ctx: LoginContext, ctype: String): List<WalletCredential> {
        val walletCredentials = findCredentials(ctx) {
            ctype in it.toW3CCredentialJwt().vc.type.orEmpty()
        }
        return walletCredentials
    }

    /**
     * For every InputDescriptor iterate over all WalletCredentials and match all constraints.
     */
    suspend fun findCredentialsByPresentationDefinition(ctx: LoginContext, vpdef: PresentationDefinition): List<Pair<InputDescriptor, WalletCredential>> {
        val foundCredentials = mutableListOf<Pair<InputDescriptor, WalletCredential>>()
        val walletCredentials = listCredentials(ctx)
        for (wc in walletCredentials) {
            for (ind in vpdef.inputDescriptors) {
                if (CredentialMatcher.matchCredential(wc, ind)) {
                    foundCredentials.add(Pair(ind, wc))
                    break
                }
            }
        }
        return foundCredentials
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun findKey(ctx: LoginContext, predicate: suspend (Key) -> Boolean): Key? {
        return listKeys(ctx).firstOrNull { predicate(it) }
    }

    suspend fun findKeyByAlgorithm(ctx: LoginContext, algorithm: String): Key? {
        return findKey(ctx) { k -> k.algorithm.equals(algorithm, ignoreCase = true) }
    }

    suspend fun findKeyById(ctx: LoginContext, keyId: String): Key? {
        return findKey(ctx) { k -> k.id == keyId }
    }

    suspend fun findKeyByType(ctx: LoginContext, keyType: KeyType): Key? {
        return findKeyByAlgorithm(ctx, keyType.algorithm)
    }

    suspend fun listKeys(ctx: LoginContext): List<Key> {
        val res: Array<KeyResponse> = api.keys(ctx)
        return res.map { kr -> Key(kr.keyId.id, kr.algorithm) }
    }

    suspend fun createKey(ctx: LoginContext, keyType: KeyType): Key {
        val kid = api.keysGenerate(ctx, keyType)
        return findKeyById(ctx,kid)!!
    }

    suspend fun signWithDid(ctx: LoginContext, did: String, message: String): String {
        val keyId = findDid(ctx) { d -> d.did == did }?.keyId
            ?: throw IllegalStateException("No such did: $did")
        return signWithKey(ctx, keyId, message)
    }

    suspend fun signWithKey(ctx: LoginContext, alias: String, message: String): String {
        return api.keysSign(ctx, alias, message)
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    suspend fun findDid(ctx: LoginContext, predicate: suspend (DidInfo) -> Boolean): DidInfo? {
        return listDids(ctx).firstOrNull { predicate(it) }
    }

    suspend fun findDidByPrefix(ctx: LoginContext, prefix: String): DidInfo? {
        return findDid(ctx) { d -> d.did.startsWith(prefix) }
    }

    suspend fun getDefaultDid(ctx: LoginContext, ): DidInfo {
        return findDid(ctx) { d -> d.default }
            ?: throw IllegalStateException("No default did for: $ctx.walletId")
    }

    suspend fun getDidDocument(ctx: LoginContext, did: String): String {
        val didInfo = api.did(ctx, did)
        return didInfo
    }

    suspend fun listDids(ctx: LoginContext): List<DidInfo> {
        val dids = api.dids(ctx)
        return dids.toList()
    }

    suspend fun createDidKey(ctx: LoginContext, alias: String, keyId: String): DidInfo {
        val req = CreateDidKeyRequest(alias, keyId)
        val did: String = api.didsCreateDidKey(ctx, req)
        val didInfo = api.dids(ctx).first { di -> di.did == did }
        return didInfo
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun getCredentialId(credJwt: SignedJWT): String {
        val credClaims = Json.Default.parseToJsonElement("${credJwt.jwtClaimsSet}") as JsonObject
        val vc = credClaims["vc"] as? JsonObject ?: throw IllegalArgumentException("No 'vc' claim")
        return vc["id"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("No 'vc.id' claim")
    }

    private fun withConnection(block: () -> Unit) {
        if (!dataSource.isInitialized()) {
            Database.Companion.connect(dataSource.value)
        }
        block()
    }
}