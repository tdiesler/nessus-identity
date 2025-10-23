<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <#if credOffer??>
            <!-- Show textarea with the CredentialOffer -->
            <h5>Generated Credential Offer</h5>
            <textarea class="height4" readonly>${credOffer?html}</textarea>

            <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
                <p>
                    Here we have the Credential Offer as seen by the Holder.
                </p>
            </div>
        <#else>
            <h5>Create a credential offer</h5>
            <form action="/issuer/credential-offer" method="get" style="max-width: 400px;">
                <hidden name="subjectId" value="${subInfo.id}"/>
                <div class="bx--form-item-horizontal">
                    <label for="subjectId" class="bx--label">Subject</label>
                    <input type="text" name="subjectId" class="bx--text-input" value="${subInfo.name} - ${subInfo.email}" readonly/>

                    <label for="ctype" class="bx--label">Credential Type</label>
                    <input type="text" name="ctype" class="bx--text-input" value="${ctype}" readonly/>
                </div>
                <div class="bx--form-item" style="margin-top: 1rem;">
                    <button type="submit" class="bx--btn bx--btn--primary">Send Offer</button>
                </div>
            </form>

            <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
                <p>
                    Issuance of a Verifiable credential starts with the Issuer making a Credential Offer. Then there is some
                    back-channel communication between the Issuer and the Holder's Wallet. The Holder hence
                    receives the Credential Offer e.g. in form of a Json file, a QR code or some link that the Issuer provides.
                </p>
                <p>
                    Only because the Holder receives an Credential Offer does not mean that she has to trust it. In contrary, it is the
                    resposibility of the Holder to verify that the Credential Offer comes from a known Issuer and is of a known type.
                    The <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer" target="_blank">OID4VCI Spec</a>
                    has no provision for individual claim key/value pairs, nor is the Credential Offer required to be signed by the Issuer.
                </p>
                <p>
                    If all is well, the Holder can accept the Credential Offer, authenticate with the Issuer and request a Credential that
                    corresponds to the Credential Offer. Then Holder than needs to validate Credential i.e. verify its content and signature.
                </p>
            </div>
        </#if>
    </div>
</@layout.layout>
