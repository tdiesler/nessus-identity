package io.nessus.identity.service

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.portal.AbstractServiceTest
import io.nessus.identity.waltid.Max
import kotlinx.serialization.json.jsonArray
import org.junit.jupiter.api.Test

class IssuerServiceTest : AbstractServiceTest() {

    @Test
    fun issuerMetadata() {

        val ctx = userLogin(Max)

        val metadataUrl = IssuerService.getIssuerMetadataUrl(ctx)
        metadataUrl.shouldEndWith("/issuer/${ctx.subjectId}/.well-known/openid-credential-issuer")

        val jsonObj = IssuerService.getIssuerMetadata(ctx).toJSON()
        jsonObj["credentials_supported"].shouldNotBeNull().jsonArray
    }
}