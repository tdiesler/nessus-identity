<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet-sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Wallet</h1>
        <h4>${holderName}</h4>
        <h5>Credential Details</h5>
        <textarea readonly>${credObj?html}</textarea>
    </div>
</@layout.layout>
