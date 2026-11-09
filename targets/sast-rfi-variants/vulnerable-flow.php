<?php

function aliasInclude() {
    $origin = "https://plugins.example.invalid/module.php";
    $alias = $origin;
    // ruleid: php-remote-file-inclusion
    $result = include($alias);
    return $result;
}

function splitScheme() {
    $scheme = "https";
    $path = $scheme . "://plugins.example.invalid/module.php";
    // ruleid: php-remote-file-inclusion
    return require $path;
}

function unknownHost($host) {
    $path = "https://" . $host . "/module.php";
    // ruleid: php-remote-file-inclusion
    include_once $path;
}

function remoteMapping() {
    $paths = ["remote" => "https://plugins.example.invalid/module.php"];
    $path = $paths["remote"];
    // ruleid: php-remote-file-inclusion
    require_once $path;
}
