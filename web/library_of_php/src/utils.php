<?php

class Page {
    public $search = '';
    private $alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .?/*;`';
    private $page = '';
    private $seed = 0;
    private $owners = [];
    public function __construct($q, $owner) {
        $this->search = $q;
        if (gettype($q) !== 'string') {
            die('Invalid input');
        }
        $this->validate();
        for ($i = 0; $i < strlen($q); $i++) {
            $this->seed += ord($q[$i]);
        }
        $this->seed = ($this->seed % 1000000) * 1000000;
        $this->calcPage();
        mt_srand($this->seed);
        $this->owners[$owner] = uniqid();
    }

    public function generateResults($name) {
        ob_start();
        $results = '';
        for ($i = 0; $i < 10000; $i++) {
            $results .= $this->alpha[mt_rand(0, strlen($this->alpha) - 1)];
        }
        echo "Discoverer: ";
        if ($this->owners[$name]) {
            echo $this->owners[$name] . '<br><br>';
        }
        $results = substr($results, 0, strlen($results) - strlen($this->search));
        $t = mt_rand(0, strlen($results));
        echo substr($results, 0, $t) . '<b>' . htmlspecialchars($this->search, ENT_QUOTES, 'UTF-8') . '</b>' . substr($results, $t);
        $f = './tmp/' . uniqid() . '.txt';
        $files = glob('./tmp/*'); // get all file names
        foreach($files as $file){ 
            if(is_file($file)) {
                unlink($file); 
            }
        }
        file_put_contents($f,  ob_get_contents());
        ob_end_clean(); // xss mitigations.
        return $f;
    }

    public function getPage() {
        return $this->page;
    }

    private function validate() {
        if (strlen($this->search) > 300) {
            die('Search string too long');
        }
        for ($i = 0; $i < strlen($this->search); $i++) {
            if (strpos($this->alpha, $this->search[$i]) === false) {
                die('Invalid characters in search string');
            }
        }
    }

    private function calcPage() {
        $s = strrev((string) $this->seed);
        $this->page = substr($s, 0, 1) . 'v-' . substr($s, 1, 4) . 'h-' . substr($s, 5, strlen($s));
    }
}
//library

function addBook($book, $path) {
    $_SESSION[$book] = $path;
}

function getBook($book) {
    return file_get_contents($_SESSION[$book]);
}

function getBookPath($book) {
    return $_SESSION[$book];
}
