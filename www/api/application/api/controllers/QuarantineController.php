<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * index page controller
 */

class QuarantineController extends Zend_Controller_Action
{

  public function init()
  {
    $this->_helper->layout->disableLayout();
    $this->_helper->viewRenderer->setNoRender(true);
  }

  public function getspamAction()
  {
     $request = $this->getRequest();
     $api = new Api_Model_QuarantineAPI();
     $api->getSpam($request->getParams());
  }

}
