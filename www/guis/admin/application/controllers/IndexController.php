<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 *
 * index page controller
 */

class IndexController extends Zend_Controller_Action {

  public function init() {
    $layout = Zend_Layout::getMvcInstance();
    $view=$layout->getView();
    $view->headLink()->appendStylesheet($view->css_path.'/main.css');
    $view->headLink()->appendStylesheet($view->css_path.'/navigation.css');
    $view->headScript()->appendFile($view->scripts_path.'/index.js', 'text/javascript');

  #  	$main_menus = Zend_Registry::get('main_menu')->findOneBy('id', 'Management')->class = 'menuselected';
  #  	$view->selectedMenu = 'Management';
  #  	$main_menus = Zend_Registry::get('main_menu')->findOneBy('id', 'submanage_Users')->class = 'submenuelselected';
  #  	$view->selectedSubMenu = 'Domains';
  }

  public function indexAction() {
  }

  public function globalstatsAction() {
    $layout = Zend_Layout::getMvcInstance();
    $view=$layout->getView();
    $layout->disableLayout();
    $view->addScriptPath(Zend_Registry::get('ajax_script_path'));

    $request = $this->getRequest();

    $stats_type = $request->getParam('t');
    if (!isset($stats_type) || !$stats_type || $stats_type == '') {
      $stats_type = 'global';
    }
    $reporting = new Default_Model_ReportingStats();
    $what = array();
		$what['stats'] = $reporting->getTodayStatElements($stats_type);
    $data = $reporting->getTodayValues($what, 0, $stats_type);

    $view->graphlink = $view->baseurl.'/index/todaypie/c/1';
    if ($request->getParam('t') != '') {
      $view->graphlink .= '/t/'.$stats_type.'/r/'.uniqid();
    }

    $view->stats_type = $stats_type;
    $total = 0;
    foreach ($data as $d) {
      $total += $d;
    }
    $view->stats_total = $total;
    $view->stats = $data;

    $template = Zend_Registry::get('default_template');
    include_once(APPLICATION_PATH . '/../public/templates/'.$template.'/css/pieColors.php');
    $view->colors = $data_colors;
  }

  public function globalstatusAction() {
    $layout = Zend_Layout::getMvcInstance();
    $view=$layout->getView();
    $layout->disableLayout();
    $view->addScriptPath(Zend_Registry::get('ajax_script_path'));

    $replica = new Default_Model_Slave();
    $replicas = $replica->fetchAll();

    $res = array();

    foreach (array('hardware', 'spools', 'load') as $service) {
      $res[$service] = array('status' => 'ok', 'message' => '', 'value' => '');
      foreach ($replicas as $s) {
        $tmpres = $s->getStatus($service);
        if ($tmpres['status'] != 'ok') {
          $res[$service]['status'] = $tmpres['status'];
          $res[$service]['message'] = $tmpres['message'];
          $res[$service]['value'] = $tmpres['value'];
          continue;
        }
        $res[$service]['status'] = $tmpres['status'];
        $res[$service]['message'] = $tmpres['message'];
        $res[$service]['value'] = $tmpres['value'];
      }
    }

    $users = 0;
    foreach ($replicas as $s) {
      $susers = $s->getTodayStats('users');
      if (is_numeric($susers)) {
        $users = max($users, $susers);
      }
    }
    $view->users = $users;

    $domain = new Default_Model_Domain();
    $domains = $domain->fetchAllName();
    $view->domains = count($domains);
    $view->distinctdomains = $domain->getDistinctDomainsCount();
    $view->hosts = (count($replicas));
    $view->status = $res;

    $config = new SpamTagger_Config();
	}

	public function todaypieAction() {
		$this->_helper->viewRenderer->setNoRender();
		$this->_helper->layout->disableLayout();
		$layout = Zend_Layout::getMvcInstance();
		$view=$layout->getView();

		$request = $this->getRequest();

		$usecache = false;
		if (preg_match('/^[A-Za-z0-9]+$/', $request->getParam('c'))) {
			$usecache = $request->getParam('c');
		}
		$type = $request->getParam('t');
		if (isset($type) && !preg_match('/^(accepted|refused|global|delayed|relayed|sessions)$/', $type)) {
			echo "invalid selection: $type";
			exit();
		}

		$reporting = new Default_Model_ReportingStats();
		$what = array();
		$what['stats'] = $reporting->getTodayStatElements();
		return $reporting->getTodayPie($what, 0, $usecache, $request->getParam('t'));
	}

}

