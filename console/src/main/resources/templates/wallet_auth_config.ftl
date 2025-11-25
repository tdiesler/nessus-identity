<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Wallet</h1>
        <h2>${walletName}</h2>
        <p>Authorization Config URL: <a href="${authConfigUrl}" target="_blank">${authConfigUrl}</a></p>
        <textarea readonly>${authConfigJson?html}</textarea>
    </div>
</@layout.layout>
