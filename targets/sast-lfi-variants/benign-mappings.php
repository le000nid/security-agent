<?php

function fixedMappingValue() {
    $choice = $_GET["page"];
    $pages = ["home" => "views/home.php", "help" => "views/help.php"];
    $path = $pages[$choice] ?? "views/home.php";
    // ok: php-local-file-inclusion
    include $path;
}

function fixedMappingWithCookieKey() {
    $choice = $_COOKIE["theme"];
    $pages = ["light" => "themes/light.php", "dark" => "themes/dark.php"];
    $path = $pages[$choice] ?? "themes/light.php";
    // ok: php-local-file-inclusion
    require_once $path;
}
