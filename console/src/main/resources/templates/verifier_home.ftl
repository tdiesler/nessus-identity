<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier_sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Verifier</h1>

        <#if verifierAuth.hasAuthToken >
            <h2>${verifierName}</h2>
            <table>
                <tr><td>VerifierDid&nbsp;</td><td><input type="text" class="bx--text-input" value="${verifierDid}" style="width: 600px;" readonly autofocus/></td></tr>
                <tr><td>TargetUri&nbsp;</td><td><input type="text" class="bx--text-input" value="${verifierUri}" style="width: 600px;" readonly/></td></tr>
            </table>
        </#if>

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
                <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html" target="_blank">Verifiable Presentations 1.0</a>.
            </p>
        </div>
    </div>
</@layout.layout>
