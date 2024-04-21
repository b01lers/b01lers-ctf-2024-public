<?php session_start()?>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="./styles/search.css">
</head>
<body>
    <div class="navbar">
        <div class="navbar-links">
            <li>
                <a href="/index.php">Click to go back</a>
            </li>
        </div>
    </div>
    <br>
    <?php
        include 'utils.php';
        include 'errorhandler.php';
        if ($_SERVER['REQUEST_METHOD'] != 'GET') {
            die('Invalid Request!');
        }
        if (!isset($_GET['s']) || !is_string($_GET['s'])) {
            die();
        }
        if (isset($_GET['securify'])) {
            $securify = $_GET['securify'];
        }
        else {
            $securify = '';
        }
        if (!isset($_GET['d']) || !is_numeric($_GET['d'])) {
            $d = rand(0, getrandmax());
        }
        else {
            $d = $_GET['d'];
        }
        if (hash('sha256', $d + rand(0, getrandmax())) === $securify) {
            include getBookPath($_GET['s']);
        }
        else {
            echo getBook($_GET['s']);
        }
        
    ?>
</body>
</html>