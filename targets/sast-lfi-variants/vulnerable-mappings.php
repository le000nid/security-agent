<?php

function untrustedMappingValue() {
    $pages = ["home" => $_GET["page"]];
    $path = $pages["home"];
    // ruleid: php-local-file-inclusion
    include $path;
}

function overwrittenMapping() {
    $pages = ["home" => "views/home.php"];
    $pages["home"] = filter_input(INPUT_POST, "override");
    $path = $pages["home"];
    // ruleid: php-local-file-inclusion
    require_once $path;
}
