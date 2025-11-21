package io.nessus.identity.service

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widDidService
import java.util.*

object W3CCredentialValidator {

    val log = KotlinLogging.logger {}

    suspend fun validateCredential(authContext: AuthorizationContext, signedJwt: SignedJWT): Pair<String, CredentialFormat> {

        val credJwt = W3CCredentialJwt.fromEncoded("${signedJwt.serialize()}")
        val credType = credJwt.types.first { it !in listOf("VerifiableAttestation", "VerifiableCredential") }

        val issuerMetadata = authContext.getIssuerMetadata()
        val format = requireNotNull(issuerMetadata.getCredentialFormat(credType)) { "No credential format for: $credType" }

        // Resolve issuer
        val issuerId = requireNotNull(credJwt.iss) { "No issuer claim" }
        log.info { "IssuerId: $issuerId" }

        // [TODO #331] Verify VC signature when iss is not did:key:*
        // https://github.com/tdiesler/nessus-identity/issues/331
        when {
            issuerId.startsWith("did:key:") -> {

                // Resolve DID Document locally
                val key = widDidService.resolveToKey(issuerId).getOrThrow()
                val jwk = JWK.parse("${key.exportJWKObject()}")
                log.info { "Issuer Jwk: $jwk" }

                val ecdsaVerifier = ECDSAVerifier(jwk.toECKey())
                when (credJwt) {
                    is W3CCredentialV11Jwt -> {
                        check(signedJwt.verify(ecdsaVerifier)) { "Invalid credential signature" }
                    }

                    is W3CCredentialSdV11Jwt -> {
                        val combined = "${signedJwt.serialize()}"
                        val jwsCompact = combined.substringBefore('~')  // keep only JWS
                        val jwsObj = JWSObject.parse(jwsCompact)
                        check(jwsObj.verify(ecdsaVerifier)) { "Invalid credential signature" }
                    }
                }
            }
        }

        // Validate JWT standard claims
        signedJwt.jwtClaimsSet.run {
            val now = Date()
            check(notBeforeTime == null || !now.before(notBeforeTime)) { "Credential not yet valid" }
            check(expirationTime == null || !now.after(expirationTime)) { "Credential expired" }
            check(this.issuer == issuerId) { "Issuer mismatch" }
        }

        return Pair(credType, format)
    }
}