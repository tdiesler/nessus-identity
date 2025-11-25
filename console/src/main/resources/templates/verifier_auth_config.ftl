<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Verifier</h1>
        <h2>${verifierName}</h2>
        <p>Authorization Config URL: <a href="${authConfigUrl}" target="_blank">${authConfigUrl}</a></p>
        <textarea readonly>${authConfigJson?html}</textarea>
    </div>
</@layout.layout>
