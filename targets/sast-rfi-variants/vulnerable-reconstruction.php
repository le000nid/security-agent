<?php

function rebuiltAfterBasename($host) {
    $filename = basename("https://plugins.example.invalid/module.php");
    $path = "https://" . $host . "/" . $filename;
    // ruleid: php-remote-file-inclusion
    include $path;
}

function rebuiltAfterPathExtraction() {
    $localPath = parse_url("https://plugins.example.invalid/module.php", PHP_URL_PATH);
    $path = "https://mirror.example.invalid" . $localPath;
    // ruleid: php-remote-file-inclusion
    require_once $path;
}
