<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h4>${holderName}</h4>
        <h5>Available Credential Offers</h5>

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
    </div>
</@layout.layout>
