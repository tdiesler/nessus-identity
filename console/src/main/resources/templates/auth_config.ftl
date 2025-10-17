<#import "layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>
        <p>Authorization Config URL: <a href="${authConfigUrl}" target="_blank">${authConfigUrl}</a></p>
        <textarea readonly>${authConfigJson?html}</textarea>
    </div>
</@layout.layout>
