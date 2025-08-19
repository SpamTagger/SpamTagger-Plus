<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * main api interface entry point
 */

// Define path to application directory
defined('APPLICATION_PATH')
    || define('APPLICATION_PATH', realpath(dirname(__FILE__) . '/../application'));

// Define application environment
defined('APPLICATION_ENV')
    || define('APPLICATION_ENV', (getenv('APPLICATION_ENV') ? getenv('APPLICATION_ENV') : 'production'));


// Ensure library/ is on include_path
set_include_path(implode(PATH_SEPARATOR, array(
    realpath(APPLICATION_PATH . '/../application'),
    realpath(APPLICATION_PATH . '/../application/api'),
    realpath(APPLICATION_PATH . '/../application/api/models'),
    realpath(APPLICATION_PATH . '/../application/library'),
    realpath(APPLICATION_PATH . '/../../guis/admin/application/models'),
    realpath(APPLICATION_PATH . '/../../guis/admin/application/library'),
    get_include_path(),
)));

ini_set('error_reporting', E_ALL);

/** Zend_Application */
require_once 'Zend/Application.php';

// Create application, bootstrap, and run
$application = new Zend_Application(
    APPLICATION_ENV,
    APPLICATION_PATH . '/api/configs/application.ini'
);
$application->bootstrap()
            ->run();
