<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

class STSoap_Quarantine
{

  /**
   * This function will fetch information on quarantined message
   *
   * @param  array  params
   * @return array
   */
  static public function Quarantine_findSpam($params) {
    $id = 0;
    if (isset($params['id'])) {
      $id = $params['id'];
    }
    if (!$id || !preg_match('/^(\d{8})\/([a-z,A-Z,0-9]{6}-[a-z,A-Z,0-9]{6,11}-[a-z,A-Z,0-9]{2,4})$/', $id, $matches)) {
      return array('status' => 0, 'error' => 'BADMSGID ('.$id.")");
    }
    $id = $matches[2];
    if (!isset($params['recipient']) || !preg_match('/^(\S+)\@(\S+)$/', $params['recipient'], $matches)) {
      return array('status' => 0, 'error' => 'BADRECIPIENT');
    }
    require_once('SpamTagger/Config.php');
    $stconfig = SpamTagger_Config::getInstance();

    $file = $stconfig->getOption('VARDIR').'/spam/'.$matches[2].'/'.$params['recipient'].'/'.$id;

    $ret['file'] = $file;
    $ret['status'] = 1;
    return $ret;
  }

}
