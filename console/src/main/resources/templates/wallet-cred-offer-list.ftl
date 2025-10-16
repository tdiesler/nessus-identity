<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Wallet</h1>
        <h4>${holderName}</h4>
        <h5>Available Credential Offers</h5>

        <#if credentialOffers?size gt 0>
        <table class="bx--data-table bx--data-table--compact" style="width: auto; table-layout: auto;">
            <thead>
                <tr><th>Issuer</th><th>Types</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <#list credentialOffers as v>
                    <tr>
                        <td>${v[1]}</td>
                        <td>${v[2]}</td>
                        <td>
                            <a href="/wallet/credential-offer/${v[0]}/view">view</a>
                            <a href="/wallet/credential-offer/${v[0]}/accept">accept</a>
                            <a href="/wallet/credential-offer/${v[0]}/delete">delete</a>
                        </td>
                    </tr>
                </#list>
            </tbody>
        </table>
        </#if>
    </div>
</@layout.layout>
