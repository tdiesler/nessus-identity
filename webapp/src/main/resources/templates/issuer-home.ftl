<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Issuer</h1>
        <p>This is the Issuer main content area.</p>
    </div>
</@layout.layout>
