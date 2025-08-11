<?php 
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

error_reporting('E_ALL');
ini_set('display_errors', 1);

$fileparam = $_REQUEST['file'];

if (!isset($fileparam)) {
    header("HTTP/1.0 404 Not Found");
    echo "Bad parameters";
    exit();
}

if (preg_match('/(\.\.|[\/\{\}$\*\?\[\]])/', $fileparam, $illegal)) {
    header("HTTP/1.0 404 Not Found");
    echo "Illegal pattern $illegal[1]";
    flush();
    exit();
}

require_once($_SERVER['DOCUMENT_ROOT'].'/../../guis/admin/application/library/SpamTagger/Config.php');
$stconfig = SpamTagger_Config::getInstance();

$file = preg_replace('/\-/', '/', $fileparam);

$file = $stconfig->getOption('VARDIR')."/log/".$file;
if (!file_exists($file)) {
    header("HTTP/1.0 404 Not Found");
    echo "File not found ($file)";
    exit();
}

$handle = fopen($file, "r");

header("Content-Type: application/octet-stream; "); 
header("Content-Transfer-Encoding: binary"); 
header("Content-Length: " . filesize($file) ."; "); 
header("filename=\"".$fileparam."\"; "); 
flush();

while(!feof($handle)) {
	$data = fread($handle, 8192);
	
	echo $data;
	flush();
}
fclose($handle);
?>
