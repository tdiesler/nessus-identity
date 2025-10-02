// This scipt verifies whether we can access the IOD4VCI Issuer Metadata from Java
//
// jbang bin/oid4vci_metadata.java https://oauth.nessustech.io
// java oid4vci_metadata.java https://oauth.nessustech.io

import java.net.http.*;
import java.net.*;

public class oid4vci_metadata {

    public static void main(String[] args) throws Exception {
        String rootUrl = (args.length > 0) ? args[0] : "https://oauth.localtest.me";
        String metadataUrl = rootUrl + "/realms/oid4vci/.well-known/openid-credential-issuer";

        HttpClient http = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder(URI.create(metadataUrl)).GET().build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());

        System.out.println("Fetching metadata from: " + metadataUrl);
        System.out.println("Status: " + res.statusCode());
        System.out.println(res.body());
    }
}
