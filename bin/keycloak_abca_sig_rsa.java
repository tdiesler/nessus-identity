///usr/bin/env jbang "$0" "$@" ; exit $?

//DEPS org.keycloak:keycloak-core:26.5.6
//DEPS org.bouncycastle:bcprov-jdk18on:1.82
//DEPS org.bouncycastle:bcpkix-jdk18on:1.82
//DEPS com.fasterxml.jackson.core:jackson-databind:2.19.2

import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Arrays;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class keycloak_abca_sig_rsa {

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        String kid = "openid-abca-attester-key";
        String cn = "github.com/keycloak";

        // ---- 1. Generate keypair (same as KC default provider)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kp.getPrivate();

        // ---- 2. Generate self-signed cert (same pattern KC uses)
        X500Name subject = new X500Name("CN=" + cn);

        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 3650L * 24 * 60 * 60 * 1000);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSAandMGF1")
                .setProvider("BC")
                .build(priv);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                        subject, serial, notBefore, notAfter, subject, pub);

        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        // ---- 3. Wrap like Keycloak does
        KeyWrapper key = new KeyWrapper();
        key.setKid(kid);
        key.setUse(KeyUse.SIG);
        key.setAlgorithm("PS256");
        key.setType("RSA");

        key.setPublicKey(pub);
        key.setPrivateKey(priv);
        key.setCertificate(cert);
        key.setCertificateChain(List.of(cert));

        // ---- 4. Convert to full JWK (private + public)
        Map<String,Object> jwk = toJwk(key);

        // ---- 5. JWKS
        Map<String,Object> jwks = Map.of("keys", List.of(jwk));

        ObjectMapper om = new ObjectMapper();
        System.out.println(om.writerWithDefaultPrettyPrinter().writeValueAsString(jwks));
    }

    static Map<String,Object> toJwk(KeyWrapper key) throws Exception {

        RSAPublicKey pub = (RSAPublicKey) key.getPublicKey();
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) key.getPrivateKey();

        String x5c = Base64.getEncoder()
                .encodeToString(key.getCertificate().getEncoded());

        Map<String,Object> jwk = new LinkedHashMap<>();

        jwk.put("kty", "RSA");
        jwk.put("kid", key.getKid());
        jwk.put("use", "sig");
        jwk.put("alg", key.getAlgorithmOrDefault());

        jwk.put("n", b64url(pub.getModulus()));
        jwk.put("e", b64url(pub.getPublicExponent()));

        jwk.put("d", b64url(priv.getPrivateExponent()));
        jwk.put("p", b64url(priv.getPrimeP()));
        jwk.put("q", b64url(priv.getPrimeQ()));
        jwk.put("dp", b64url(priv.getPrimeExponentP()));
        jwk.put("dq", b64url(priv.getPrimeExponentQ()));
        jwk.put("qi", b64url(priv.getCrtCoefficient()));

        jwk.put("x5c", List.of(x5c));

        return jwk;
    }

    static String b64url(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b[0] == 0) {
            b = Arrays.copyOfRange(b, 1, b.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}