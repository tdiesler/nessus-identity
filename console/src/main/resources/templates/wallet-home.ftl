<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Wallet</h1>
        <h4>${holderName}</h4>

        Subject DID: <input type="text" class="bx--text-input" value="${holderDid}" style="width: 400px;" readonly autofocus/>
    </div>
</@layout.layout>
