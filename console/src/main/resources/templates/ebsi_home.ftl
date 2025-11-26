<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="ebsi">
    <!-- Sidebar -->
    <#include "fragments/ebsi_sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>EBSI Conformance</h1>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <h2>Request and present Verifiable Credentials</h2>

            The Holder Wallet module checks the wallet's ability to handle credential requests, authentication and presentation to verifiers on demand.
            <p/>

            <#if holderAuth.hasAuthToken>
                <h3>${walletName}</h3>
                <input type="text" value="${walletDid}" size="80" readonly/>
                <h3>Wallet Endpoint</h3>
                <input type="text" value="${walletUri}" size="80" readonly/>
            </#if>

            <p/>
            Go to the <a href="https://hub.ebsi.eu/wallet-conformance/holder-wallet" target="_blank">start tests</a> page for holder wallets and
            <i>Insert your DID</i> and <i>Credential Offer Endpoint</i> from above. Then use "No" for QR code reading capabilities.
            To run the first test, pull down <i>In-time Credential</i> and click <i>Initiate (credential offering redirect)</i>

            <p/>
            If all goes well, the browser should show the credential that ebsi has just issued.
            It should also show up in your <a href="${demoWalletUrl}" target="_blank">wallet</a>.

            <hr/> <!--------------------------------------------------------------------------------------------------->

            <h2>Issue Verifiable Credentials</h2>

            The Issuer to Holder module checks the credential issuance process from an issuer to a Holder wallet
            <p/>

            <#if issuerAuth.hasAuthToken>
                <h3>${issuerName}</h3>
                <input type="text" value="${issuerDid}" size="80" readonly/>
                <h3>Issuer Endpoint</h3>
                <input type="text" value="${issuerUri}" size="80" readonly/>
                <p/>
                Issuer Metadata: <a href="${issuerUri}/.well-known/openid-credential-issuer" target="_blank">${issuerUri}/.well-known/openid-credential-issuer"</a><br/>
                Authorization Metadata: <a href="${issuerUri}/.well-known/openid-configuration" target="_blank">${issuerUri}/.well-known/openid-configuration"</a><br/>
            </#if>

            <p/>
            Go to <a href="https://hub.ebsi.eu/wallet-conformance/issue-to-holder" target="_blank">Issue Verifiable Credentials</a>, start tests and
            <i>Insert your DID</i> and <i>Client ID</i> from above. To run the first test, pull down <i>In-time Credential</i> and click
            <i>Initiate</i> and then <i>Validate</i>.

            <p/>
            If all goes well, both buttons should switch to "Yes". The issuer does not keep a copy of the credential.

            <hr/> <!--------------------------------------------------------------------------------------------------->

            <h2>Request and verify Verifiable Credentials</h2>

            The Verify module checks the capability to validate and verify Verifiable Credentials and Presentations.
            <p/>
            <#if verifierAuth.hasAuthToken>
                <h3>${verifierName}</h3>
                <input type="text" value="${verifierDid}" size="80" readonly/>
                <h3>Verifier Endpoint</h3>
                <input type="text" value="${verifierUri}" size="80" readonly/>
            </#if>

            <p/>
            Go to <a href="https://hub.ebsi.eu/wallet-conformance/verifier" target="_blank">Request and verify Verifiable Credentials</a>, start tests and
            <i>Insert your Client ID</i> from above. To run the first test, pull down <i>Verifiable Presentations</i> and click
            <i>Validate</i>.

            <p/>
            If all goes well, the button should switch to "Yes". The verifier does not keep a copy of the presentation.
        </div>
    </div>
</@layout.layout>
