<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h2>${walletName}</h2>
        <h3>Available Credential Offer</h3>

        <!-- Show textarea with the CredentialOffer -->
        <textarea class="height4" readonly>${credOffer?html}</textarea>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <#if isUserPinRequired == "true" >
                <p>
                    Get the current value for the user PIN from <a href="https://hub.ebsi.eu/wallet-conformance/holder-wallet/flow" target="_blank">here</a>
                </p>
            </#if>
            <form method="get" style="margin-top: 1rem;">
                <#if isUserPinRequired == "true" >
                <div class="bx--form-item-horizontal">
                    <label for="userPin" class="bx--label">UserPin</label>
                    <input name="userPin" id="userPin" class="bx--input" style="width: 120px;" placeholder="${defaultUserPin}" required/>
                </div>
                </#if>
                <div class="bx--form-item-horizontal" style="width: 120px;">
                    <button type="submit" class="bx--btn bx--btn--primary" formaction="/wallet/credential-offer/${credOfferId}/accept">accept</button>
                    <button type="submit" class="bx--btn bx--btn--primary" formaction="/wallet/credential-offer/${credOfferId}/delete">delete</button>
                </div>
            </form>
        </div>
    </div>
</@layout.layout>
