///usr/bin/env jbang "$0" "$@" ; exit $?

//DEPS org.bitcoinj:bitcoinj-core:0.17

import java.util.Base64;
import java.io.ByteArrayOutputStream;
import org.bitcoinj.base.Base58;

public class Es256ToDidKey {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: jbang Es256ToDidKey.java <x_b64url> <y_b64url>");
            System.exit(1);
        }

        byte[] x = Base64.getUrlDecoder().decode(args[0]);
        byte[] y = Base64.getUrlDecoder().decode(args[1]);

        if (x.length != 32 || y.length != 32)
            throw new IllegalArgumentException("x,y must be 32 bytes for P-256");

        // Uncompressed point: 0x04 | X | Y
        byte[] pub = new byte[1 + 32 + 32];
        pub[0] = 0x04;
        System.arraycopy(x, 0, pub, 1, 32);
        System.arraycopy(y, 0, pub, 33, 32);

        // Multicodec prefix 0x1200u -> KeyType.secp256r1
        byte[] prefix = uvarint(0x1200);
        byte[] prefixed = concat(prefix, pub);

        String did = "did:key:z" + Base58.encode(prefixed);
        System.out.println(did);
    }

    static byte[] uvarint(int value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            int b = value & 0x7F;
            value >>>= 7;
            if (value == 0) {
                out.write(b);
                break;
            } else {
                out.write(b | 0x80);
            }
        }
        return out.toByteArray();
    }

    static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }
}
