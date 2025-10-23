<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="verifier">
    <!-- Sidebar -->
    <#include "fragments/verifier_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Verifier</h1>

        <h5>VP Token Header</h5>
        <textarea class="height1" readonly>${vpTokenHeader?html}</textarea>

        <h5>VP Token Claims</h5>
        <textarea class="height4" readonly>${vpTokenClaims?html}</textarea>

        <h5>Presentation Credentials</h5>
        <textarea class="height4" readonly>${verifiableCredentials?html}</textarea>

        <h5>Presentation Submission</h5>
        <textarea class="height2" readonly>${submissionJson?html}</textarea>
    </div>
</@layout.layout>
