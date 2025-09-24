<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <#if credentialOffer??>
            <!-- Show textarea with the CredentialOffer -->
            <p>Generated Credential Offer</p>
            <textarea id="credentialOfferBox" style="width:100%; min-height: 300px; font-family: monospace; margin-top: 1rem;"
            readonly>${credentialOffer?html}
            </textarea>
            <button type="button" class="bx--btn bx--btn--secondary" style="margin-top: 1rem;"
            onclick="copyToClipboard('credentialOfferBox')"> Copy
            </button>
        <#else>
            <p>Create a credential offer</p>
            <form action="/issuer/credential-offer" method="post" style="margin-top: 20px; max-width: 400px;">
                <div class="bx--form-item-horizontal">
                    <label for="ctype" class="bx--label">Credential Type</label>
                    <input type="text" name="ctype" class="bx--text-input" value="${ctype}" readonly/>
                    <label for="subjectId" class="bx--label">Subject DID</label>
                    <input type="text" name="subjectId" class="bx--text-input" placeholder="did:key:1234" required autofocus/>
                </div>
                <div class="bx--form-item" style="margin-top: 1rem;">
                    <button type="submit" class="bx--btn bx--btn--primary">Create</button>
                </div>
            </form>
        </#if>
    </div>
</@layout.layout>
