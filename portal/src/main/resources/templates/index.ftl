<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <title>Nessus Identity</title>
        <style>
            body { font-family: sans-serif; background-color: #f9f9f9; }
            .code-block {
                background-color: #f0f0f0;
                padding: 0.2em;
                font-family: monospace;
                white-space: pre;
                overflow-x: auto;
                display: none;
            }
        </style>
        <script>
            function toggleCode() {
                const block = document.getElementById("jsonBlock");
                const isHidden = getComputedStyle(block).display === "none";
                block.style.display = isHidden ? "block" : "none";
            }
        </script>
    </head>
    <body>
        <h3>Nessus Identity - EBSI Conformance Portal</h3>

        <#if hasWalletId && hasDidKey>
            <p/>
            ${walletName}
            <table>
                <tr>
                    <td>Subject Did</td>
                    <td><input type="text" value="${did!}" size="80" readonly/>&nbsp;<a style="font-size: small;" href="/logout">logout</a></td>
                </tr>
            </table>
        <#elseif hasWalletId && !hasDidKey>
            <p/>
            ${walletName}
            <#if !did??>
                <p/>
                Please create did:key:jwk_jcs-pub identifier from ECDSA_Secp256r1 key algorithm in the <a href="${devWalletUrl}" target="_blank">Dev Wallet</a><br/>
                i.e. first create a private key with that algirithm, then a 'did:key:...' from that private key. Then <a href="/logout">logout</a> and login again.
            </#if>
        <#else>
            <form id="loginForm" method="post" action="/login">
                <table>
                    <tr>
                        <td><label for="email">Email:</label></td>
                        <td><input type="email" id="email" name="email" value="user@email.com" required /></td>
                    </tr>
                    <tr>
                        <td><label for="password">Password:</label></td>
                        <td><input type="password" id="password" name="password" value="password" required /></td>
                        <td>
                            <a style="font-size: small;" href="#" onclick="document.getElementById('loginForm').submit(); return false;">login</a>
                            <a style="font-size: small;" href="${demoWalletUrl}" target="_blank">register</a>
                        </td>
                    </tr>
                </table>
            </form>
        </#if>

        <hr/> <!-------------------------------------------------------------------------------------------------------->

        <h3>Learn about EBSI</h3>
        <ul>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows">Issue Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows">Hold Credentials</a></li>
            <li><a href="https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows">Verify Credentials</a></li>
        </ul>

        <#if hasDidKey>

            <h3>View Metadata</h3>
            <table>
                <tr>
                    <td>EBSI</td>
                    <td><a href="https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/.well-known/openid-credential-issuer">Issuer</a></td>
                    <td><a href="https://api-conformance.ebsi.eu/conformance/v3/auth-mock/.well-known/openid-configuration">Auth</a></td>
                </tr>
                <tr>
                    <td>Nessus</td>
                    <td><a href="/issuer/${subjectId}/.well-known/openid-credential-issuer">Issuer</a></td>
                    <td><a href="/auth/${subjectId}/.well-known/openid-configuration">Auth</a></td>
                </tr>
            </table>

            <h3>Service</h3>
            <ul>
                <li><a href="${demoWalletUrl}" target="_blank">Demo Wallet</a></li>
                <li><a href="${devWalletUrl}" target="_blank">Dev Wallet</a></li>
            </ul>

            <hr/> <!--------------------------------------------------------------------------------------------------->

            <h4>Request and present Verifiable Credentials</h4>

            The Holder Wallet module checks the wallet's ability to handle credential requests, authentication and presentation to verifiers on demand.

            <p/>
            Wallet Endpoint
            <input type="text" value="${walletUri}" size="80" readonly/>

            <p/>
            Go to the <a href="https://hub.ebsi.eu/wallet-conformance/holder-wallet" target="_blank">start tests</a> page for holder wallets and
            <i>Insert your DID</i> and <i>Credential Offer Endpoint</i> from above. Then use "No" for QR code reading capabilities.
            To run the first test, pull down <i>In-time Credential</i> and click <i>Initiate (credential offering redirect)</i>

            <p/>
            If all goes well, the browser should <button onclick="toggleCode()">show</button> the credential that ebsi has just issued.
            It should also show up in your <a href="${demoWalletUrl}" target="_blank">wallet</a>.

<pre id="jsonBlock" class="code-block"><code>
{
    "sub": "${did}",
    "nbf": 1748613301,
    "iss": "did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD",
    "exp": 1748699706,
    "iat": 1748613301,
    "vc": {
        "@context": [ "https://www.w3.org/2018/credentials/v1" ],
        "credentialSchema": {
            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
            "type": "FullJsonSchemaValidator2021"
        },
        "credentialSubject": {
            "id": "${did}"
        },
        "expirationDate": "2025-05-31T13:55:06Z",
        "id": "vc:ebsi:conformance#6bbeae8a-a7f5-41a7-949a-8c675a1262ef",
        "issuanceDate": "2025-05-30T13:55:01Z",
        "issued": "2025-05-30T13:55:01Z",
        "issuer": "did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD",
        "type": [
            "VerifiableCredential",
            "VerifiableAttestation",
            "CTWalletSameAuthorisedInTime"
        ],
        "validFrom": "2025-05-30T13:55:01Z",
        "termsOfUse": {
            "id": "https://api-conformance.ebsi.eu/trusted-issuers-registry/v5/issuers/did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD/attributes/bcdb6bc952c8c897ca1e605fce25f82604c76c16d479770014b7b262b93c0250",
            "type": "IssuanceCertificate"
        }
    },
    "jti": "vc:ebsi:conformance#6bbeae8a-a7f5-41a7-949a-8c675a1262ef"
}
</code></pre>

            <hr/> <!--------------------------------------------------------------------------------------------------->

            <h4>Issue Verifiable Credentials</h4>

            The Issuer to Holder module checks the credential issuance process from an issuer to a Holder wallet
            <p/>
            Issuer Endpoint
            <input type="text" value="${issuerUri}" size="80" readonly/>

            <p/>
            Go to <a href="https://hub.ebsi.eu/wallet-conformance/issue-to-holder" target="_blank">Issue Verifiable Credentials</a>, start tests and
            <i>Insert your DID</i> and <i>Client ID</i> from above. To run the first test, pull down <i>In-time Credential</i> and click
            <i>Initiate</i> and then <i>Validate</i>.

            <p/>
            If all goes well, both buttons should switch to "Yes". The issuer does not keep a copy of the credential.
            <i>[TODO] perhaps we can show the issued credential in this portal.</i>

            <hr/> <!--------------------------------------------------------------------------------------------------->

            <h4>Request and verify Verifiable Credentials</h4>

            The Verify module checks the capability to validate and verify Verifiable Credentials and Presentations.
            <p/>
            Auhorization Endpoint (Client ID)
            <input type="text" value="${authUri}" size="80" readonly/>

            <p/>
            Go to <a href="https://hub.ebsi.eu/wallet-conformance/verifier" target="_blank">Request and verify Verifiable Credentials</a>, start tests and
            <i>Insert your Client ID</i> from above. To run the first test, pull down <i>Verifiable Presentations</i> and click
            <i>Validate</i>.

            <p/>
            If all goes well, the button should switch to "Yes". The verifier does not keep a copy of the presentation.
            <i>[TODO] perhaps we can show the verified credential in this portal.</i>

        </#if>
    </body>
</html>
