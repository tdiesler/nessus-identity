<div class="sidebar">
    <ul class="menu-items">
        <#if holderAuth.hasAuthToken>
            <li class="bx--list__item">
                <a href="/wallet/login" class="inactive">Login</a>
                <a href="/wallet/logout">Logout</a>
            </li>
            <li class="bx--list__item"><a href="/wallet/keys" class="inactive">Keys</a></li>
            <li class="bx--list__item"><a href="/wallet/dids" class="inactive">DIDs</a></li>
            <li class="bx--list__item"><a href="/wallet/credential-offers">Credential Offers</a></li>
            <li class="bx--list__item"><a href="/wallet/credentials">Credentials</a></li>
        <#else>
            <li class="bx--list__item">
                <a href="/wallet/login">Login</a>
                <a href="/wallet/logout" class="inactive">Logout</a>
            </li>
            <li class="bx--list__item"><a href="/wallet/keys" class="inactive">Keys</a></li>
            <li class="bx--list__item"><a href="/wallet/dids" class="inactive">DIDs</a></li>
            <li class="bx--list__item"><a href="/wallet/credential-offers"class="inactive">Credential Offers</a></li>
            <li class="bx--list__item"><a href="/wallet/credentials"class="inactive">Credentials</a></li>
        </#if>
    </ul>
</div>
