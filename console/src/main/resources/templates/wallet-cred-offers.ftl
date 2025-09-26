<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Wallet</h1>
        <h4>${holderName}</h4>
        <h5>Available Credential Offers</h5>
        <ul class="bx--list--unordered">
            <#list credentialOffers as p>
                <li class="bx--list__item">${p.second}
                    <a href="/wallet/credential-offer/${p.first}/accept">accept</a>
                    <a href="/wallet/credential-offer/${p.first}/delete">delete</a>
                </li>
            </#list>
        </ul>
    </div>
</@layout.layout>
