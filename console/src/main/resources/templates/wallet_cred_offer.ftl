<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Wallet</h1>
        <h4>${holderName}</h4>
        <h5>Available Credential Offer</h5>

        <!-- Show textarea with the CredentialOffer -->
        <textarea class="half-height" readonly>${credOffer?html}</textarea>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <a href="/wallet/credential-offer/${credOfferId}/accept">accept</a>
            <a href="/wallet/credential-offer/${credOfferId}/delete">delete</a>
            <p>
                Here we have the Credential Offer as seen by the Holder.
            </p>
        </div>
    </div>
</@layout.layout>
