<?php
    function BabelErrorHandler($errno, $errstr, $errfile, $errline) {
        if (!(error_reporting() & $errno)) {
            return;
        }

        switch ($errno) {
            case E_USER_ERROR:
            echo "<b>BABEL ERROR</b> [$errno] $errstr<br />\n";
            echo "  Fatal error on line $errline in file $errfile";
            echo ", PHP " . PHP_VERSION . " (" . PHP_OS . ")<br />\n";
            echo "Aborting...<br />\n";
            exit(1);
            break;

        case E_USER_WARNING:
            echo str_replace(['"', "'"], '', "<b>BABEL WARNING</b> [$errno] $errstr");
            break;

        case E_USER_NOTICE:
            echo str_replace(['"', "'"], '', "<b>Babel Notice</b>: [$errno] $errstr");
            break;

        default:
            echo str_replace(['"', "'"], '', "<b>Unknown Babel Type</b> [$errno] $errstr");
            break;
        }
        return true;
    }

set_error_handler("BabelErrorHandler");