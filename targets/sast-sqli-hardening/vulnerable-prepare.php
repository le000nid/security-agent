<?php

// Case 1: unsafe PDO prepare

$id = $_GET["id"];

$sql = "SELECT * FROM users WHERE id = " . $id;

$pdo->prepare($sql);


// Case 2: unsafe mysqli_prepare

$email = $_POST["email"];

$query = "SELECT * FROM users WHERE email = '" . $email . "'";

mysqli_prepare($connection, $query);