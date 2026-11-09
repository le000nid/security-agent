<?php

function queryInclude() {
    $supplied = $_GET["page"];
    if ($supplied !== "home") {
        return;
    }
    // ok: php-local-file-inclusion
    include "views/home.php";
}

function postIncludeOnce() {
    $supplied = $_POST["template"];
    if ($supplied !== "profile") {
        return;
    }
    // ok: php-local-file-inclusion
    include_once("templates/profile.php");
}

function requestRequire() {
    $supplied = $_REQUEST["module"];
    if ($supplied !== "dashboard") {
        return;
    }
    // ok: php-local-file-inclusion
    require "modules/dashboard.php";
}

function cookieRequireOnce() {
    $supplied = $_COOKIE["theme"];
    if ($supplied !== "light") {
        return;
    }
    // ok: php-local-file-inclusion
    require_once("themes/light.php");
}
