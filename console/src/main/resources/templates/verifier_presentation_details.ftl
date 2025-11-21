<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Verifier</h1>

        <h3>VP Token Header</h3>
        <textarea class="height1" readonly>${vpTokenHeader?html}</textarea>

        <h3>VP Token Claims</h3>
        <textarea class="height4" readonly>${vpTokenClaims?html}</textarea>

        <h3>Presentation Credentials</h3>
        <textarea class="height4" readonly>${verifiableCredentials?html}</textarea>

        <h3>Presentation Submission</h3>
        <textarea class="height2" readonly>${submissionJson?html}</textarea>
    </div>
</@layout.layout>
