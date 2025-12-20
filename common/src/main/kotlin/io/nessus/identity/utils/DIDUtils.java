package io.nessus.identity.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * Utility methods for DID encoding/decoding, specifically did:key for P-256 (ES256).
 * <p>
 * Provides:
 * - EC → did:key:z... encoding (multibase + multicodec + base58btc)
 * - did:key → EC public key decoding
 * - multicodec varint encode/decode
 * - EC point normalization
 * <p>
 *
 * @author <a href="mailto:tdiesler@ibm.com">Thomas Diesler</a>
 */
public final class DIDUtils {

    private DIDUtils() {
    }

    /**
     * Multicodec identifier for P-256 public keys.
     * See: https://github.com/multiformats/multicodec/
     * <p>
     * Codec name: "p256-pub"
     * Code: 0x1200 (varint-encoded into bytes: 0x80 0x24)
     */
    public static final int MULTICODEC_P256_PUB = 0x1200;
    public static final int MULTICODEC_P384_PUB = 0x1201;
    public static final int MULTICODEC_P521_PUB = 0x1202;

    // ---------------------------------------------------------------------
    // Public API – did:key encoding / decoding
    // ---------------------------------------------------------------------

    /**
     * Encode a ECPublicKey (P-256) into a did:key representation.
     */
    public static String encodeDidKey(ECPublicKey pub) {
        try {
            return encodeDidKeyInternal(pub);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decode a did:key (P-256) into an ECPublicKey.
     */
    public static ECPublicKey decodeDidKey(String did) {
        try {
            ECPublicKey pubKey = decodeDidKeyInternal(did);
            return pubKey;
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static int getDidKeyCodec(String did) {
        if (did==null || !did.startsWith("did:key:z"))
            return 0;

        // Strip "did:key:z" (z = multibase base58btc)
        String base58 = did.substring("did:key:z".length());
        byte[] decoded = Base58.decode(base58);

        // Read multicodec varint (LEB128)
        int codec = 0;
        int shift = 0;

        for (byte value : decoded) {
            int b = value & 0xff;
            codec |= (b & 0x7f) << shift;
            if ((b & 0x80)==0) {
                break;
            }
            shift += 7;
        }

        return switch (codec) {
            case MULTICODEC_P256_PUB, MULTICODEC_P384_PUB, MULTICODEC_P521_PUB -> codec;
            default -> 0;
        };
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private static String encodeDidKeyInternal(ECPublicKey pub) throws IOException {

        ECParameterSpec params = pub.getParams();
        int fieldSize = params.getCurve().getField().getFieldSize();

        // Verify P-256 => secp256r1
        if (fieldSize!=256) {
            throw new IllegalArgumentException("Expected secp256r1, but key uses: " + params);
        }

        byte[] x = toUnsigned32(pub.getW().getAffineX().toByteArray());
        byte[] y = toUnsigned32(pub.getW().getAffineY().toByteArray());

        // Write multicodec varint: 0x1200 → 0x80 0x24
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeVarint(MULTICODEC_P256_PUB, baos);

        // EC uncompressed point format: 0x04 || X || Y
        baos.write(0x04);
        baos.write(x);
        baos.write(y);

        String didKey = "did:key:z" + Base58.encode(baos.toByteArray());
        return didKey;
    }

    private static ECPublicKey decodeDidKeyInternal(String did) throws GeneralSecurityException, IOException {

        if (!did.startsWith("did:key:z")) {
            throw new IllegalArgumentException("Unsupported DID format: " + did);
        }

        String b58 = did.substring("did:key:z".length());
        InputStream in = new ByteArrayInputStream(Base58.decode(b58));

        // Read and verify multicodec varint
        int codec = readVarint(in);
        if (codec!=MULTICODEC_P256_PUB) {
            throw new IllegalArgumentException("Unexpected multicodec: 0x" + Integer.toHexString(codec));
        }

        // Expect 0x04 indicating an uncompressed EC point
        int tag = in.read();
        if (tag!=0x04) {
            throw new IllegalArgumentException("Invalid EC point tag: " + tag);
        }

        byte[] x = readNBytes(in, 32);
        byte[] y = readNBytes(in, 32);

        ECPoint point = new ECPoint(
                new BigInteger(1, x),
                new BigInteger(1, y)
        );

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec paramSpec = params.getParameterSpec(ECParameterSpec.class);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, paramSpec);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKey pubKey = (ECPublicKey) keyFactory.generatePublic(keySpec);
        return pubKey;
    }

    // ---------------------------------------------------------------------
    // Multicodec varint (LEB128) encoding / decoding
    // ---------------------------------------------------------------------

    private static void writeVarint(int value, OutputStream out) throws IOException {
        while ((value & ~0x7F)!=0) {
            out.write((value & 0x7F) | 0x80); // continuation bit
            value >>>= 7;
        }
        out.write(value);
    }

    private static int readVarint(InputStream in) throws IOException {
        int value = 0;
        int shift = 0;

        while (true) {
            int b = in.read();
            if (b==-1) {
                throw new EOFException("EOF while reading varint");
            }

            value |= (b & 0x7F) << shift;

            if ((b & 0x80)==0) {
                break; // final byte
            }

            shift += 7;
            if (shift > 28) {
                throw new IllegalArgumentException("Varint too long");
            }
        }

        return value;
    }

    // ---------------------------------------------------------------------
    // EC utility helpers
    // ---------------------------------------------------------------------

    // Read exactly n bytes from the given InputStream
    //
    private static byte[] readNBytes(InputStream in, int n) throws IOException {
        int read = 0;
        byte[] bytes = new byte[n];
        while (read < n) {
            int r = in.read(bytes, read, bytes.length - read);
            if (r==-1)
                throw new IllegalStateException("Unexpected EOF");
            read += r;
        }
        return bytes;
    }

    // Convert a signed BigInteger byte array into a fixed 32-byte unsigned array.
    // Removes sign byte or pads with zeros as needed.
    private static byte[] toUnsigned32(byte[] in) {
        if (in.length==32) {
            return in;
        }
        if (in.length > 32) {
            // strip sign byte
            return Arrays.copyOfRange(in, in.length - 32, in.length);
        }
        // pad to 32 bytes
        byte[] out = new byte[32];
        System.arraycopy(in, 0, out, 32 - in.length, in.length);
        return out;
    }
}
