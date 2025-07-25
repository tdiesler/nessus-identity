package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test

class AuthServiceTest : AbstractServiceTest() {

    @Test
    fun authMetadata() {
        runBlocking {
            val ctx = login(Max)

            val metadataUrl = AuthService.getAuthMetadataUrl(ctx)
            metadataUrl.shouldEndWith("/auth/${ctx.targetId}/.well-known/openid-configuration")

            val jsonObj = AuthService.getAuthMetadata(ctx)
            jsonObj.shouldNotBeNull()
        }
    }
}