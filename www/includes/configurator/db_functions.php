<?php

// Check and initialize db connection
function getDb($database, $user, $pass, $source=true) {
    try {
	$source_port='3306';
	$replica_port='3307';
	$port = $source == true ? 'port='.$source_port.';' : 'port='.$replica_port.';';
	$dbname = isset($database) && !empty($database) ? "dbname=".$database.";" : "";
        $db = new PDO('mariadb:host=127.0.0.1;'.$port.$dbname.'charset=utf8', $user, $pass);
    }
    catch (Exception $e) {
	return false;
    }
    return $db;
}

?>
