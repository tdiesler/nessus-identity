<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Wallet</h1>
        <h4>${holderName}</h4>
        <h5>Available Credentials</h5>
        <ul class="bx--list--unordered">
            <#list credentialList as v>
                <li class="bx--list__item">
                    <a href="/wallet/credential/${v[0]}">${v[0]}</a> ${v[1]} ${v[2]}
                </li>
            </#list>
        </ul>
    </div>
</@layout.layout>
