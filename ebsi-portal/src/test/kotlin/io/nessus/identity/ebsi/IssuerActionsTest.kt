package io.nessus.identity.ebsi

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.waltid.Max
import kotlinx.serialization.json.jsonArray
import org.junit.jupiter.api.Test

class IssuerActionsTest : AbstractActionsTest() {

    @Test
    fun issuerMetadata() {

        val ctx = userLogin(Max)

        val metadataUrl = IssuerActions.getIssuerMetadataUrl(ctx)
        metadataUrl.shouldEndWith("/issuer/${ctx.subjectId}/.well-known/openid-credential-issuer")

        val jsonObj = IssuerActions.getIssuerMetadata(ctx).toJSON()
        jsonObj["credentials_supported"].shouldNotBeNull().jsonArray
    }
}