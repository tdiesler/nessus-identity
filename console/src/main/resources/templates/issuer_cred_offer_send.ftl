<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <h3>Send a Credential Offer</h3>
        <table class="bx--data-table bx--data-table--compact" style="width: auto; table-layout: auto;">
            <tbody>
                <tr>
                    <td>Configuration</td><td>${configId}</td>
                </tr>
                <tr>
                    <td>Subject</td><td>${holder.name}</td>
                </tr>
                <tr>
                    <td>Offer Uri</td><td><a href="${credOfferUri}" target="_blank">${credOfferUri}</a></td>
                </tr>
                <tr>
                    <td><img src="data:image/png;base64,${credOfferQRCode}" alt="QR code" style="margin-top: 1rem; width: 200px; height: 200px;"/></td>
                </tr>
            </tbody>
        </table>
        <#if holder.email?has_content && holderAuth.hasAuthToken>
        <form action="/issuer/credential-offer/send" method="post">
            <div class="bx--form-item-horizontal">
                <input type="hidden" name="credOfferUri" value="${credOfferUri}"/>
            </div>
            <div class="bx--form-item" style="margin-top: 1rem;">
                <button type="submit" class="bx--btn bx--btn--primary">Send Offer</button>
            </div>
        </form>
        </#if>
    </div>
</@layout.layout>
