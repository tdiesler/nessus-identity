<#import "layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h4>${holderName}</h4>
        <h5>Credential Details</h5>
        <textarea readonly>${credObj?html}</textarea>
    </div>
</@layout.layout>
