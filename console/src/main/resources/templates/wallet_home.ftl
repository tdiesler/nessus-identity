<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Holder</h1>

        <#if holderAuth.hasAuthToken>
            <h2>${holderName}</h2>
            Subject DID: <input type="text" class="bx--text-input" value="${holderDid}" style="width: 400px;" readonly autofocus/>
        </#if>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <p>
                This is the Holder's main content area.
            </p>
            <p>
                On the left we have links to wallet admin tasks like managing Keys and DIDs for a given Wallet. This functionality
                can all be delegated to the <a href="https://waltid-wallet-api.localtest.me" target="_blank">WaltId API</a>
                or to the <a href="https://waltid-wallet-dev.localtest.me" target="_blank">Dev Wallet</a> and is currently
                not (yet) supported in this console.
            </p>
            <p>
                We also have access to Credential Offers that the Holder already knows about. Note, that this is currently not
                delegated tho the WaltId API because it has no notion of EBSI compliant Credential Offers.
            </p>
            <p>
                Finally, we see the list of Credentials that the Holder already holds.
            </p>
            <p>
                Holder functionality is defined by
                <ul class="bx--list--unordered bx--list">
                    <li class="bx--list__item">
                        <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html" target="_blank">Verifiable Credential Issuance 1.0</a>
                    </li>
                    <li class="bx--list__item">
                        <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html" target="_blank">Verifiable Presentations 1.0</a>
                    </li>
                </ul>
            </p>
        </div>
    </div>
</@layout.layout>
