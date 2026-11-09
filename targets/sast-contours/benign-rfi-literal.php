<?php

// Known local modules only. No remote URL reaches include/require.
$module = $_GET["module"] ?? "home";

switch ($module) {
    case "help":
        require(__DIR__ . "/modules/help.php");
        break;
    default:
        require(__DIR__ . "/modules/home.php");
        break;
}
