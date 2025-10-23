<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="holder">
    <!-- Sidebar -->
    <#include "fragments/holder_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Holder</h1>
        <h4>${holderName}</h4>
        <h5>Available Credentials</h5>

        <table class="bx--data-table bx--data-table--compact" style="width: auto; table-layout: auto;">
            <thead>
                <tr><th>Issuer</th><th>Types</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <#list credentials as vc>
                    <tr>
                        <td>${vc[1]}</td>
                        <td>${vc[2]}</td>
                        <td>
                            <a href="/wallet/credential/${vc[0]}">view</a>
                            <a href="/wallet/credential/${vc[0]}/delete">delete</a>
                        </td>
                    </tr>
                </#list>
            </tbody>
        </table>
        <#if credentials?size gt 0>
        <div style="margin-top: 1em;">
            <a href="/wallet/credential/__all__/delete">delete all</a>
        </div>
        </#if>
    </div>
</@layout.layout>
