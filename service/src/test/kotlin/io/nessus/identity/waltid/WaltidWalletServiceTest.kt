package io.nessus.identity.waltid

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import id.walt.oid4vc.data.dif.PresentationDefinition
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import io.nessus.identity.service.AbstractServiceTest
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Test

class WaltidWalletServiceTest : AbstractServiceTest() {

    // Authentication --------------------------------------------------------------------------------------------------

    @Test
    fun userLogin() {
        runBlocking {
            val ctx = widWalletSvc.login(Max.toLoginParams())
            ctx.authToken.shouldNotBeBlank()
            ctx.maybeWalletInfo.shouldBeNull()
        }
    }

    // Account ---------------------------------------------------------------------------------------------------------

    @Test
    fun listWallets() {
        runBlocking {
            val ctx = login(Max)
            val wallets = widWalletSvc.listWallets(ctx)
            wallets.shouldNotBeEmpty()
        }
    }

    // Credentials -----------------------------------------------------------------------------------------------------

    @Test
    fun listCredentials() {
        runBlocking {
            val ctx = loginWithWallet(Max)
            val credentials = widWalletSvc.listCredentials(ctx)
            credentials.shouldNotBeNull()
        }
    }

    @Test
    fun findCredentials() {

        val json = loadResourceAsString("presentation-definition.json")
        val vpdef = Json.Default.decodeFromString<PresentationDefinition>(json)

        runBlocking {
            val ctx = loginWithWallet(Max)
            widWalletSvc.findCredentialsByPresentationDefinition(ctx, vpdef)
        }
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    @Test
    fun listKeys() {
        runBlocking {
            val ctx = loginWithWallet(Max)
            val keys = widWalletSvc.listKeys(ctx)
            keys.shouldNotBeEmpty()
        }
    }

    @Test
    fun createKey() {
        runBlocking {
            val ctx = loginWithWallet(Max)
            val key = widWalletSvc.createKey(ctx, KeyType.SECP256R1)
            key.algorithm shouldBe KeyType.SECP256R1.algorithm
        }
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    @Test
    fun listDids() {
        runBlocking {
            val ctx = loginWithWallet(Max)
            val res = widWalletSvc.listDids(ctx)
            res.shouldNotBeEmpty()
        }
    }

    @Test
    fun createDidKey() {
        runBlocking {
            val ctx = loginWithWallet(Max)
            val keys = widWalletSvc.listKeys(ctx)
            val alias = "did:key#${keys.size + 1}"
            widWalletSvc.findDidByPrefix(ctx, "did:key") ?: runBlocking {
                val key = widWalletSvc.findKeyByType(ctx, KeyType.SECP256R1)
                val didInfo = widWalletSvc.createDidKey(ctx, alias, key?.id ?: "")
                didInfo.did.shouldNotBeBlank()
            }
        }
    }

    @Test
    fun signVerifyWithDid() {
        runBlocking {
            val ctx = loginWithWallet(Max)
            val didInfo = widWalletSvc.findDidByPrefix(ctx,"did:key").shouldNotBeNull()
            val signJwt = widWalletSvc.signWithDid(ctx, didInfo.did, "Kermit")
            signJwt.shouldNotBeBlank()

            val docJson = Json.Default.parseToJsonElement(didInfo.document).jsonObject
            val verificationMethods = docJson["verificationMethod"] as JsonArray
            val verificationMethod = verificationMethods.let { it[0] as JsonObject }
            val publicKeyJwk = Json.Default.encodeToString(verificationMethod["publicKeyJwk"])

            val publicJwk = ECKey.parse(publicKeyJwk)
            val verifier = ECDSAVerifier(publicJwk)

            // JWT-style split
            val parts = signJwt.split('.')
            parts.size shouldBe 3

            val header = JWSHeader.parse(Base64URL.from(parts[0]))
            val signature = Base64URL.from(parts[2])

            val signedContent = "${parts[0]}.${parts[1]}"
            val success = verifier.verify(header, signedContent.toByteArray(), signature)
            success shouldBe true
        }
    }

    // Logout ----------------------------------------------------------------------------------------------------------

    @Test
    fun userLogout() {
        runBlocking {
            widWalletSvc.logout()
        }
    }
}