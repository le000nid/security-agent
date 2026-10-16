<?php

function localAfterBasename() {
    $filename = basename("https://plugins.example.invalid/module.php");
    $path = "views/" . $filename;
    // ok: php-remote-file-inclusion
    include $path;
}

function localAfterPathExtraction() {
    $localPath = parse_url("https://plugins.example.invalid/module.php", PHP_URL_PATH);
    $path = "/srv/application" . $localPath;
    // ok: php-remote-file-inclusion
    require_once $path;
}
