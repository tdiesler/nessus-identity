<div class="sidebar">
    <ul class="menu-items">
        <#if keycloakUrl?has_content >
            <li class="bx--list__item"><a href="${keycloakUrl}" target="_blank">Keycloak</a></li>
        </#if>
        <li class="bx--list__item"><a href="/issuer/auth-config">Auth Config</a></li>
        <li class="bx--list__item"><a href="/issuer/issuer-config">Issuer Config</a></li>
        <li class="bx--list__item"><a href="/issuer/credential-offers">Credential Offers</a></li>
        <li class="bx--list__item"><a href="/issuer/users">Users</a></li>
    </ul>
</div>
