<?php session_start()?>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="./styles/index.css">
</head>
<body>
    <h1 class="title">Welcome to the Library of</h1>
    <img class="title" src="php.png" alt="php" width="100">
    <p class="title">Inspired by the Library of Babel</p>
    <form action="/index.php" method="POST">
        <input type="text" name="q">
        <input type="submit" value="Search">
    </form>
    <div class="search-res">
        <?php
            include 'utils.php';
            include 'errorhandler.php';
            if ($_SERVER['REQUEST_METHOD'] != 'POST') {
                die('Search for something!');
            }
            if (!isset($_POST['q']) || !is_string($_POST['q'])) {
                die('Search for something!');
            }
            $username = NULL;
            if (isset($_COOKIE['username']) && is_string($_COOKIE['username'])) {
                $username = $_COOKIE['username'];
            }
            $page = new Page($_POST['q'], $username ? substr($_COOKIE['PHPSESSID'], -6) : 'guest'); //6 is probably unique enough
            $username = isset($username) ? substr($_COOKIE['PHPSESSID'], -6) : 'guest'; 
            echo '<h1>Search results for: ' . htmlspecialchars($_POST['q'], ENT_QUOTES, 'UTF-8') . '</h1>';
            $r = $page->generateResults($username);
            echo 'Found at shelf <a href="/search.php?s=' . $page->getPage() . '">' .  $page->getPage() . '</a><br><br>';
        ?>
        <div class="results">
            <?php
                echo file_get_contents($r);
                addBook($page->getPage(), $r);
                // unlink($r);
            ?>
        </div>
    </div>
</body>
</html>
