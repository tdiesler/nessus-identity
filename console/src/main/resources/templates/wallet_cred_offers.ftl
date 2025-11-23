<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h2>${holderName}</h2>
        <h3>Available Credential Offers</h3>

        <table class="bx--data-table bx--data-table--compact" style="width: auto; table-layout: auto;">
            <thead>
                <tr><th>Issuer</th><th>Types</th><th>PreAuth</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <#list credentialOffers as vco>
                    <tr>
                        <td>${vco[1]}</td>
                        <td>${vco[2]}</td>
                        <td>${vco[3]}</td>
                        <td>
                            <a href="/wallet/${targetId}/credential-offer/${vco[0]}/view">view</a>
                            <a href="/wallet/${targetId}/credential-offer/${vco[0]}/accept">accept</a>
                            <a href="/wallet/${targetId}/credential-offer/${vco[0]}/delete">delete</a>
                        </td>
                    </tr>
                </#list>
            </tbody>
        </table>
        <#if credentialOffers?size gt 0>
            <div style="margin-top: 1em;">
                <a href="/wallet/${targetId}/credential-offer/delete-all">delete all</a>
            </div>
        </#if>
        <div style="margin-top: 1em;">
            <h3>Initiate from EBSI CT v3.2</h3>
            <ul class="bx--list--unordered bx--list">
                <li class="bx--list__item">
                    <a href="https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletSameAuthorisedInTime&client_id=${userDid}&credential_offer_endpoint=${credentialOfferEndpoint}">
                        CTWalletSameAuthorisedInTime</a>
                </li>
            </ul>
        </div>
    </div>
</@layout.layout>
