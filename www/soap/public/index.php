<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

// Define path to application directory
defined('APPLICATION_PATH')
    || define('APPLICATION_PATH', realpath(dirname(__FILE__) . '/../application'));

// Define application environment
defined('APPLICATION_ENV')
    || define('APPLICATION_ENV', (getenv('APPLICATION_ENV') ? getenv('APPLICATION_ENV') : 'production'));

// Ensure library/ is on include_path
set_include_path(implode(PATH_SEPARATOR, array(
    realpath(APPLICATION_PATH . '/../application/'),
    realpath(APPLICATION_PATH . '/../../guis/admin/application/models'),
    realpath(APPLICATION_PATH . '/../../guis/admin/application/library'),
    get_include_path(),
)));

ini_set('error_reporting', E_ALL  & ~E_STRICT & ~E_DEPRECATED);
ini_set('display_errors', 'off');

$url = 'http://';
if (isset($_SERVER['HTTPS'])) {
	$url = 'https://';
}
#$url .= $_SERVER['SERVER_NAME'].":".$_SERVER['SERVER_PORT'].$_SERVER['REQUEST_URI']."?wsdl";
$url .= 'localhost'.":".$_SERVER['SERVER_PORT'].$_SERVER['REQUEST_URI']."?wsdl";

$options = array (
  'soap_version' => SOAP_1_2,
  'uri' => $url
);

require_once('SoapInterface.php');
  
if(isset($_GET['wsdl'])) {
  handleWSDL();
} else {
  handleSOAP();
}


function handleSOAP() {
  global $options;
  global $url;
  
  require_once('Zend/Soap/Server.php');
  $server = new Zend_Soap_Server($url);

#  $server->setClass('STSoap_Test');
#  $server->setObject(new STSoap_Test());
  $server->setClass('SoapInterface');
  $server->setObject(new SoapInterface());

  $server->handle();
}

function handleWSDL() {
  global $options;
  global $url;
  
  require_once('Zend/Soap/AutoDiscover.php');
  $autodiscover = new Zend_Soap_AutoDiscover();
#  $autodiscover->setClass('STSoap_Test');
  $autodiscover->setClass('SoapInterface');
  $autodiscover->handle();
}
