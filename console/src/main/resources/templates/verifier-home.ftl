<#import "layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Verifier</h1>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <p>This is the Verifier's main content area.</p>
            <p>
                On the left we have a link to a JWT Decoder that will come handy when inspecting JSON Web Tokens.
            </p>
            <p>
                The Verifier can request Credential Presentations from a Holder's Wallet.
            </p>
            <p>
                Verifier functionality is defined by
                <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html" target="_blank">OpenID for Verifiable Presentations</a>.
            </p>
        </div>
    </div>
</@layout.layout>
