<?php

$page = $_GET["page"] ?? "home";

switch ($page) {
    case "about":
        include(__DIR__ . "/pages/about.php");
        break;

    default:
        include(__DIR__ . "/pages/home.php");
        break;
}