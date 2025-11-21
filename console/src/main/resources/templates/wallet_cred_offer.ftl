<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h2>${holderName}</h2>
        <h3>Available Credential Offer</h3>

        <!-- Show textarea with the CredentialOffer -->
        <textarea class="height4" readonly>${credOffer?html}</textarea>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <a href="/wallet/${targetId}/credential-offer/${credOfferId}/accept">accept</a>
            <a href="/wallet/${targetId}/credential-offer/${credOfferId}/delete">delete</a>
            <p>
                Here we have the Credential Offer as seen by the Holder.
            </p>
        </div>
    </div>
</@layout.layout>
