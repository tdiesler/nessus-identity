<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h2>${holderName}</h2>
        <h3>Credential Details</h3>
        <textarea readonly>${credData?html}</textarea>
        <div style="margin-top: 1em;">
            <a href="/wallet/${targetId}/credential/${credId}/delete">delete</a>
        </div>
    </div>

</@layout.layout>
