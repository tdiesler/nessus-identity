package io.nessus.identity.service

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.waltid.AbstractServiceTest
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test

class AuthServiceTest : AbstractServiceTest() {

    @Test
    fun authMetadata() {
        
        val ctx = authLogin(Max)

        val metadataUrl = AuthService.getAuthMetadataUrl(ctx)
        metadataUrl.shouldEndWith("/auth/${ctx.subjectId}/.well-known/openid-configuration")

        val jsonObj = AuthService.getAuthMetadata(ctx)
        jsonObj.shouldNotBeNull()
    }
}