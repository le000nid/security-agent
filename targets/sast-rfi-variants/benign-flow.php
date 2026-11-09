<?php

function remoteValueIsOnlyAKey() {
    $choice = "https://plugins.example.invalid/module.php";
    $paths = ["home" => "views/home.php"];
    $path = $paths[$choice] ?? "views/home.php";
    // ok: php-remote-file-inclusion
    $result = include($path);
    return $result;
}

function extractedFilename() {
    $remote = "https://plugins.example.invalid/module.php";
    $path = basename($remote);
    // ok: php-remote-file-inclusion
    return require $path;
}

function extractedUrlPath() {
    $remote = "https://plugins.example.invalid/module.php";
    $path = parse_url($remote, PHP_URL_PATH);
    // ok: php-remote-file-inclusion
    include_once $path;
}

function fixedLocalPrefix() {
    $remote = "https://plugins.example.invalid/module.php";
    $path = "views/" . $remote;
    // ok: php-remote-file-inclusion
    require_once $path;
}
