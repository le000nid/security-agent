<?php

function concatenatedOrigin() {
    $origin = "https://plugins.example.invalid";
    $path = $origin . "/module.php";
    // ruleid: php-remote-file-inclusion
    include $path;
}

function formattedHost($host) {
    $path = sprintf("https://%s/module.php", $host);
    // ruleid: php-remote-file-inclusion
    require $path;
}

function interpolatedOrigin() {
    $origin = "https://plugins.example.invalid";
    $path = "$origin/module.php";
    // ruleid: php-remote-file-inclusion
    include_once $path;
}

function conditionalRemote($preferRemote) {
    $path = $preferRemote ? "http://plugins.example.invalid/module.php" : "views/home.php";
    // ruleid: php-remote-file-inclusion
    require_once $path;
}
