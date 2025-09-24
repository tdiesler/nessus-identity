<#import "layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier-sidebar.ftl">

    <!-- Main content -->
    <div class="content" style="flex:1; padding:1rem;">
        <h1>OID4VC Verifier</h1>
        <p>This is the Verifier main content area.</p>
    </div>
</@layout.layout>
