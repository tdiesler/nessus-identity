<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h4>${holderName}</h4>

        <h5>Request Verifiable Presentation Consent</h5>

        <!-- Show textarea with the DCQLQuery -->
        <textarea class="height4" readonly>${dcqlQuery?html}</textarea>

        <form action="/wallet/auth/flow/vp-token-consent" method="get" style="max-width:640px;">
            <div style="display:flex; gap:0.5rem; margin-top:1rem;">
                <button type="submit" name="state" value="accept" class="bx--btn bx--btn--primary" style="padding:0.5rem 1rem;">
                    Accept
                </button>
                <button type="submit" name="state" value="deny" class="bx--btn bx--btn--primary" style="padding:0.5rem 1rem;">
                    Deny
                </button>
            </div>
        </form>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <p>
                The Verifier asks the Holder for Verifiable Presentation consent.
            </p>
        </div>
    </div>
</@layout.layout>
