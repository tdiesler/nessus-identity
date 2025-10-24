package io.nessus.identity.types;

import com.google.protobuf.CodedOutputStream;
import org.bitcoinj.base.Base58;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;

import static io.nessus.identity.service.HttpUtilsKt.base64UrlDecode;

class DidGeneratorTest {

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
    @Test
    public void generateDidKey() throws Exception {

        String[] args = new String[]{"PmikqfM-pLx6ia8O6h4Uj5eEMZHsagDRLu1ZOjS0kgM", "QysPrD0dE7yaPm0SIC4US3U5xb85TrRXs-dTX4DHuew"};

        byte[] x = base64UrlDecode(args[0]);
        byte[] y = base64UrlDecode(args[1]);

        if (x.length != 32 || y.length != 32)
            throw new IllegalArgumentException("x,y must be 32 bytes for P-256");

        ByteArrayOutputStream baos = new ByteArrayOutputStream(1 + 32 + 32);
        CodedOutputStream cos = CodedOutputStream.newInstance(baos);

        // Multicodec prefix 0x1200u -> KeyType.secp256r1
        cos.writeUInt32NoTag(0x1200);
        cos.flush();

        // Uncompressed EC point: 0x04 | X | Y
        baos.write(0x04);
        baos.write(x);
        baos.write(y);

        String did = "did:key:z" + Base58.encode(baos.toByteArray());
        System.out.println(did);
    }
}
