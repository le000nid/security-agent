<?php

function localInclude() {
    // ok: php-remote-file-inclusion
    include "views/home.php";
}

function absoluteIncludeOnce() {
    // ok: php-remote-file-inclusion
    include_once("/srv/application/views/home.php");
}

function localRequire() {
    // ok: php-remote-file-inclusion
    require "views/https-module.php";
}

function localRequireOnce() {
    // ok: php-remote-file-inclusion
    require_once("./modules/http-module.php");
}
