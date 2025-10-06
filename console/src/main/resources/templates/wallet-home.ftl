<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Wallet</h1>
        <h4>${holderName}</h4>

        Subject DID: <input type="text" class="bx--text-input" value="${holderDid}" style="width: 400px;" readonly autofocus/>
        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <p>
                This is the Wallets's main content area.
            </p>
            <p>
                On the left we see links to Wallet admin tasks like managing keys and dids for a given wallet. This functionality
                can all be delegated to the <a href="https://waltid-wallet-api.localtest.me" target="_blank">WaltId API</a>
                of the <a href="https://waltid-wallet-dev.localtest.me" target="_blank">Dev Wallet</a> and is currently
                not (yet) supported in this console.
            </p>
            <p>
                Then we also have access to the Credential Offers that the Wallet already knows about. Note, that this is currently not.
                delegated tho the WaltId API because it has no notion of EBSI compliant Credential Offers.
            </p>
            <p>
                Finally, we see the list of Verifiable Credentials that the Wallet already holds.
            </p>
        </div>
    </div>
</@layout.layout>
