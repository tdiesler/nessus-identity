<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <#if credentialOffer??>
            <!-- Show textarea with the CredentialOffer -->
            <h5>Generated Credential Offer</h5>
            <textarea id="credentialOfferBox" readonly>${credentialOffer?html}</textarea>

            <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
                <p>
                    Here we have the Credential Offer as seen by the Holder. Currently it does not show the individual claims,
                    which is still a <a href="https://github.com/tdiesler/nessus-identity/issues/288" target="_blank">TODO</a>.
                </p>
            </div>
        <#else>
            <h5>Create a credential offer</h5>
            <form action="/issuer/credential-offer" method="get" style="max-width: 400px;">
                <div class="bx--form-item-horizontal">
                    <label for="ctype" class="bx--label">Credential Type</label>
                    <input type="text" name="ctype" class="bx--text-input" value="${ctype}" readonly/>
                    <label for="subjectId" class="bx--label">Subject Id</label>
                    <select name="subjectId" id="subjectId" class="bx--select" required>
                        <#list subjects as subj>
                            <option value="${subj.did}">
                                ${subj.name} - ${subj.email}
                            </option>
                        </#list>
                    </select>
                </div>
                <div class="bx--form-item" style="margin-top: 1rem;">
                    <button type="submit" class="bx--btn bx--btn--primary">Send Offer</button>
                </div>
            </form>

            <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
                <p>
                    Issuance of a Verifiable credential starts with the Issuer making a Credential Offer. Then there is some
                    back-channel communication between the Issuer and the wallet from the potential Holder. Hence, the Holder
                    receives the offer somehow for example in form of a Json file, a QR code or some link that the Issuer provides.
                </p>
                <p>
                    Only because the Holder receives an Offer does not mean that she has to trust it. In contrary, it is the
                    resposibility of the Holder to verify the correctness of the offered claims and the Offer's authenticity - the
                    Holder needs to verify the Offers signature to make sure that it was really sent by an Issuer that is authorized to make such offers
                </p>
                <p>
                    If all is well, the Holder can accept the Offer, authenticate with the Issuer and request a Verifiable Credential that
                    corresponds to the Offer.
                </p>
            </div>
        </#if>
    </div>
</@layout.layout>
