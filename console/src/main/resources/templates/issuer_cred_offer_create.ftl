<#import "fragments/layout.ftl" as layout>

<@layout.layout activeTab="issuer">
    <!-- Sidebar -->
    <#include "fragments/issuer_sidebar.ftl">

    <!-- Main content -->
    <div class="content">
        <h1>OID4VC Issuer</h1>

        <h3>Create a Credential Offer</h3>
        <form action="/issuer/credential-offer/create" method="post" style="max-width: 400px;">
            <div class="bx--form-item-horizontal">
                <label for="configId" class="bx--label">Configuration</label>
                <input type="text" id="configId" name="configId" class="bx--text-input" value="${configId}" readonly/>

                <label for="userId" class="bx--label">Subject</label>
                <select id="userId" name="userId" class="bx--select">
                    <option value=""></option>
                    <#list users as usr>
                        <option value="${usr.email}" <#if usr?index == 0>selected</#if>>
                            ${usr.name}
                        </option>
                    </#list>
                </select>
                <!-- Dedicated container for checkbox -->
                <div style="margin-top: 1rem; display: flex; align-items: center; gap: 0.5rem;">
                    <input type="checkbox" id="preAuthorized" name="preAuthorized" class="bx--checkbox" value="true" checked>
                    <label for="preAuthorized" class="bx--checkbox-label">Pre-Authorized</label>
                </div>
            </div>
            <div class="bx--form-item" style="margin-top: 1rem;">
                <button type="submit" class="bx--btn bx--btn--primary">Create Offer</button>
            </div>
        </form>

        <div class="bx--type-body-long-01 bx--doc-text" style="max-width: 70ch; margin-top: 1rem;">
            <p>
                Issuance of a Verifiable credential starts with the Issuer making a Credential Offer. Then there is some
                back-channel communication between the Issuer and the Holder's Wallet. The Holder hence
                receives the Credential Offer e.g. in form of a Json file, a QR code or some link that the Issuer provides.
            </p>
            <p>
                Only because the Holder receives an Credential Offer does not mean that she has to trust it. In contrary, it is the
                resposibility of the Holder to verify that the Credential Offer comes from a known Issuer and is of a known type.
                The <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer" target="_blank">OID4VCI Spec</a>
                has no provision for individual claim key/value pairs, nor is the Credential Offer required to be signed by the Issuer.
            </p>
            <p>
                If all is well, the Holder can accept the Credential Offer, authenticate with the Issuer and request a Credential that
                corresponds to the Credential Offer. Then Holder then needs to validate Credential i.e. verify its content and signature.
            </p>
        </div>
    </div>
</@layout.layout>
