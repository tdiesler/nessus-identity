<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>OID4VC Issuer</title>
    <!-- IBM Carbon Design System -->
    <link rel="stylesheet" href="https://unpkg.com/carbon-components/css/carbon-components.min.css" />
    <link rel="stylesheet" href="/css/default.css" />
    <script defer src="https://unpkg.com/carbon-components/scripts/carbon-components.min.js"></script>
    <link rel="icon" href="/vc-key-bow.png" media="(prefers-color-scheme: light)" />
    <link rel="icon" href="/vc-key-wob.png" media="(prefers-color-scheme: dark)" />
    <script>
    function copyToClipboard(elementId) {
        const el = document.getElementById(elementId);
        el.select();
        document.execCommand("copy");
        window.getSelection().removeAllRanges();
    }
    function toggleSidebar() {
        document.getElementById("sidebar").classList.toggle("collapsed");
    }
    </script>
</head>
