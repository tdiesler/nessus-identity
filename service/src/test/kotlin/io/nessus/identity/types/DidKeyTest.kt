package io.nessus.identity.types

import io.nessus.identity.utils.DIDUtils
import io.nessus.identity.utils.base64UrlDecode
import io.nessus.identity.utils.base64UrlEncode
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import kotlin.test.assertEquals

class DidKeyTest {
    /*
        * Generate a did:key:... from a public key definition
        *
        *  curl -s https://oauth.localtest.me/realms/oid4vci/protocol/openid-connect/certs | jq -r '.keys[] | select(.alg=="ES256" and .crv=="P-256" and .use=="sig")'
        *  {
        *    "kid": "iR55bKctfGlRMMFShtTugClzDYYhqlaFOtcprIGM1nY",
        *    "kty": "EC",
        *    "alg": "ES256",
        *    "use": "sig",
        *    "crv": "P-256",
        *    "x": "PmikqfM-pLx6ia8O6h4Uj5eEMZHsagDRLu1ZOjS0kgM",
        *    "y": "QysPrD0dE7yaPm0SIC4US3U5xb85TrRXs-dTX4DHuew"
        *  }
        *
        *  did:key:z4oJ8b2Y9GQAY2aH2TWcoPxPjrSFS7V5nu1xhnFJ3HUchzycT6g37Y149FvKJxY2PQywvh1DfYbYcSSzzN66MoN3CuJYs
        */

    var args = arrayOf("PmikqfM-pLx6ia8O6h4Uj5eEMZHsagDRLu1ZOjS0kgM", "QysPrD0dE7yaPm0SIC4US3U5xb85TrRXs-dTX4DHuew")
    var expDid = "did:key:z4oJ8b2Y9GQAY2aH2TWcoPxPjrSFS7V5nu1xhnFJ3HUchzycT6g37Y149FvKJxY2PQywvh1DfYbYcSSzzN66MoN3CuJYs"

    @Test
    fun generateDidKey() {
        val x = base64UrlDecode(args[0])
        val y = base64UrlDecode(args[1])

        require(!(x.size != 32 || y.size != 32)) { "x,y must be 32 bytes for P-256" }

        val ecPoint = ECPoint(BigInteger(1, x), BigInteger(1, y))
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val ecSpec = parameters.getParameterSpec<ECParameterSpec>(ECParameterSpec::class.java)
        val pubKeySpec = ECPublicKeySpec(ecPoint, ecSpec)
        val keyFactory = KeyFactory.getInstance("EC")

        val pubKey = keyFactory.generatePublic(pubKeySpec) as ECPublicKey?
        val wasDid = DIDUtils.encodeDidKey(pubKey)

        assertEquals(expDid, wasDid)
    }

    @Test
    fun decodeDidKey() {

        val pubKey = DIDUtils.decodeDidKey(expDid)
        val x = pubKey.w.affineX
        val y = pubKey.w.affineY

        val x64 = base64UrlEncode(x.toByteArray())
        val y64 = base64UrlEncode(y.toByteArray())

        assertEquals(args[0], x64)
        assertEquals(args[1], y64)

        val codec = DIDUtils.getDidKeyCodec(expDid)
        assertEquals(DIDUtils.MULTICODEC_P256_PUB, codec)
    }
}
