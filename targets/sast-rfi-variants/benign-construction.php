<?php

function concatenatedLocal() {
    $origin = "views";
    $path = $origin . "/home.php";
    // ok: php-remote-file-inclusion
    include $path;
}

function remoteAddressIsOnlyMetadata() {
    $endpoint = sprintf("https://%s/module.php", "plugins.example.invalid");
    error_log($endpoint);
    // ok: php-remote-file-inclusion
    require "views/home.php";
}

function remoteValueWasOverwritten() {
    $path = "https://plugins.example.invalid/module.php";
    $path = "views/home.php";
    // ok: php-remote-file-inclusion
    include_once $path;
}

function conditionalLocal($preferHelp) {
    $path = $preferHelp ? "views/help.php" : "views/home.php";
    // ok: php-remote-file-inclusion
    require_once $path;
}
