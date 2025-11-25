<div id="sidebar" class="sidebar">
    <ul class="menu-items">
        <#if verifierAuth.hasAuthToken>
            <li class="bx--list__item">
                <a href="/verifier/login" class="inactive">Login</a>
                <a href="/verifier/logout">Logout</a>
            </li>
            <li class="bx--list__item"><a href="https://www.jwt.io" target="_blank">JWT Debuger</a></li>
            <li class="bx--list__item"><a href="/verifier/auth-config">Auth Config</a></li>
            <li class="bx--list__item"><a href="/verifier/presentation-request">Presentation Request</a></li>
        <#else>
            <li class="bx--list__item">
                <a href="/verifier/login">Login</a>
                <a href="/verifier/logout" class="inactive">Logout</a>
            </li>
            <li class="bx--list__item"><a href="https://www.jwt.io" target="_blank">JWT Debuger</a></li>
            <li class="bx--list__item"><a class="inactive">Auth Config</a></li>
            <li class="bx--list__item"><a class="inactive">Presentation Request</a></li>
        </#if>
    </ul>
</div>
