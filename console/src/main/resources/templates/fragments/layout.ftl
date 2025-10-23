<#macro layout activeTab>
    <!doctype html>
    <html lang="en">
        <#include "head.ftl">
        <body class="app-body">

            <!-- Role tabs row (Issuer | Holder | Verifier) -->
            <header class="app-header">
                <div class="role-links">
                    <a href="/issuer" class="<#if activeTab == 'issuer'>active-role</#if>">Issuer</a>
                    <a href="/wallet" class="<#if activeTab == 'holder'>active-role</#if>">Holder</a>
                    <a href="/verifier" class="<#if activeTab == 'verifier'>active-role</#if>">Verifier</a>
                </div>
            </header>

            <!-- Sub-app content (sidebar + page) -->
            <main class="app-main">
                <#nested>
            </main>

            <footer class="app-footer">
                &copy; 2025 Nessus Identity - ${versionInfo.version}
                <#if versionInfo.revision??>(Rev: ${versionInfo.revision})</#if>
            </footer>
        </body>
    </html>
</#macro>
