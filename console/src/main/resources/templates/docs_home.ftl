<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="docs">
    <!-- Sidebar -->
    <#include "fragments/empty_sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Docs</h1>

        <h3>EBSI</h3>
        <p>
            <ul class="bx--list--unordered bx--list">
                <li class="bx--list__item">
                    <a href="https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows" target="_blank">Issue Verifiable Credentials</a>
                </li>
                <li class="bx--list__item">
                    <a href="https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows" target="_blank">Hold and present Verifiable Credentials</a>
                </li>
                <li class="bx--list__item">
                    <a href="https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows" target="_blank">Request and verify Verifiable Credentials</a>
                </li>
                <li class="bx--list__item">
                    <a href="https://hub.ebsi.eu/wallet-conformance" target="_blank">Wallet Conformance Testing</a>
                </li>
                <li class="bx--list__item">
                    <a href="https://hub.ebsi.eu/conformance/standards-versions" target="_blank">Standards Versions</a>
                </li>
            </ul>
        </p>

        <h3>Standards</h3>
        <p>
            <ul class="bx--list--unordered bx--list">
                <li class="bx--list__item">
                    <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html" target="_blank">Verifiable Credential Issuance 1.0</a>
                </li>
                <li class="bx--list__item">
                    <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html" target="_blank">Verifiable Presentations 1.0</a>
                </li>
                <li class="bx--list__item">
                    <a href="https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515" target="_blank">Verifiable Credentials Data Model 2.0</a>
                </li>
                <li class="bx--list__item">
                    <a href="https://openid.net/specs/openid-connect-core-1_0.html" target="_blank">OpenID Connect 1.0</a>
                </li>
            </ul>
        </p>
    </div>
</@layout.layout>
