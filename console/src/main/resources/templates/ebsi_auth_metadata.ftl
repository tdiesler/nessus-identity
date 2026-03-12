<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="ebsi">
    <!-- Sidebar -->
    <#include "fragments/ebsi_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>EBSI Authorization Metadata</h1>
        <p>Authorization Metadata URL: <a href="${authMetadataUrl}" target="_blank">${authMetadataUrl}</a></p>
        <textarea readonly>${authMetadataJson?html}</textarea>
    </div>
</@layout.layout>
