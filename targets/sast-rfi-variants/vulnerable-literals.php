<?php

function remoteInclude() {
    // ruleid: php-remote-file-inclusion
    include "http://plugins.example.invalid/module.php";
}

function remoteIncludeOnce() {
    // ruleid: php-remote-file-inclusion
    include_once("https://plugins.example.invalid/module.php");
}

function remoteRequire() {
    // ruleid: php-remote-file-inclusion
    require "HtTp://plugins.example.invalid/module.php";
}

function remoteRequireOnce() {
    // ruleid: php-remote-file-inclusion
    require_once("HTTPS://plugins.example.invalid/module.php");
}
