<?php

$name = $_GET["name"];
error_log($name);
readfile("uploads/manual.txt");
