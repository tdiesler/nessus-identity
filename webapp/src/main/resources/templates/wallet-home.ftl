<#import "layout.ftl" as layout>

<@layout.layout activeTab="wallet">
    <!-- Sidebar -->
    <#include "fragments/wallet-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Wallet</h1>
        <p>This is the Wallet main content area.</p>
    </div>
</@layout.layout>
