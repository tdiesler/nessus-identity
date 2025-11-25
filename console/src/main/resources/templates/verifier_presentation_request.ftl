<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Verifier</h1>

        <h3>Request Credential Presentation</h3>

        <form action="/verifier/presentation-request" method="post" style="max-width:640px;">
            <input type="hidden" name="targetId" value="${targetId}"/>
            <div class="bx--form-item-horizontal">
                <label for="subject" class="bx--label">Subject</label>
                <input type="text" id="subject" name="subject" class="bx--text-input" value="${subInfo.name} - ${subInfo.email}" readonly/>
                <label for="ctype" class="bx--label">Credential Type</label>
                <select name="ctype" id="ctype" class="bx--select">
                    <#list vctValues as vct>
                        <option value="${vct}">${vct}</option>
                    </#list>
                </select>
                <label for="claims" class="bx--label">DCQL Claims</label>
                <textarea name="claims" id="claims" class="bx--textarea"
                    style="height:200px;font-family:monospace;width:100%;">${claimsJson?html}</textarea>
            </div>
            <div class="bx--form-item-horizontal">
                <div></div>
                <button type="submit" class="bx--btn bx--btn--primary"
                    style="width:auto; padding:0.5rem 1rem; justify-self:start;">
                    Request
                </button>
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
                resposibility of the Holder to verify that the Offer comes from a known Issuer and is of a known type.
                The <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer" target="_blank">core spec</a>
                has no provision for individual claim key/value pairs, nor it it required to be signed by the Issuer.
            </p>
            <p>
                If all is well, the Holder can accept the Offer, authenticate with the Issuer and request a Verifiable Credential that
                corresponds to the Offer.
            </p>
        </div>
    </div>
</@layout.layout>
