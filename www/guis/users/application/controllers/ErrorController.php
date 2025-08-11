<?php
/**
 * SpamTagger
 *
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @copyright 2025, SpamTagger
 */

/**
 * Error handling controller
 * @author jpgrossglauser
 */
class ErrorController extends Zend_Controller_Action
{
    public function errorAction()
    {
        $this->view->errors = $this->_getParam('error_handler');
        die(var_dump($this->view->errors));
    }
}

