<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

class STSoap_Content
{

	static public $_fieldstosend = array(
	   'id', 'size', 'from_address', 'to_address', 'to_domain', 'subject', 'virusinfected', 'nameinfected', 'otherinfected', 'report', 'date', 'time', 'content_forced'
	);
  /**
   * This function will search for quarantined content
   *
   * @param  array $params
   * @return array
   */
	static public function Content_fetchAll($params, $limit=0) {

		if (isset($params['id']) && !preg_match('/^([a-z,A-Z,0-9]{6}-[a-z,A-Z,0-9]{6,11}-[a-z,A-Z,0-9]{2,4})$/', $params['id'], $matches)) {
			unset($params['id']);
		}

		require_once('SpamTagger/Config.php');
    	$stconfig = SpamTagger_Config::getInstance();

    	require_once('Zend/Db/Adapter/Pdo/Mysql.php');
    	$contentDb = new Zend_Db_Adapter_Pdo_Mysql(array(
    	                      'host'        => 'localhost',
                              'unix_socket' => $stconfig->getOption('VARDIR')."/run/mariadb_replica/mariadbd.sock",
                              'username'    => 'spamtagger',
                              'password'    => $stconfig->getOption('MYSPAMTAGGERPWD'),
                              'dbname'      => 'st_stats'
                             ));
        $query = $contentDb->select();
        $query->from('maillog');
    #    var_dump($params);
	    if (isset($params['reference']) && $params['reference'] != '') {
        	unset($params['domain']);
        	unset($params['search']);
        	unset($params['sender']);
        	unset($params['subject']);
                unset($params['fd']);
                unset($params['fm']);
                unset($params['td']);
                unset($params['tm']);

        	if (preg_match('/(\d{8})[-\/](\S+)/', $params['reference'], $matches)) {
        		$query->where('id = ?', $matches[2]);
        	} else {
                $query->where('id = ?', $params['reference']);
        	}
        }

	    if (isset($params['domain']) && $params['domain'] != '') {
        	$query->where('to_domain = ?', $params['domain']);
        }
	    if (isset($params['search']) && $params['search'] != '') {
        	$query->where('to_address LIKE ?', $params['search'].'%');
        }
	    if (isset($params['sender']) && $params['sender'] != '') {
        	$query->where('from_address LIKE ?', $params['sender'].'%');
        }
	    if (isset($params['subject']) && $params['subject'] != '') {
        	$query->where('subject LIKE ?', '%'.$params['subject'].'%');
        }

        if (isset($params['td']) && isset($params['td']) && isset($params['tm']) && isset($params['tm'])
		  && isset($params['fd']) && isset($params['fd']) && isset($params['fm']) && isset($params['fm'])
		   ) {

            $today = getDate();
            $params['fy'] = $today['year'];
            $params['ty'] = $today['year'];
            if ($params['tm'] < $params['fm']) {
        	    $params['fy']--;
            }

         	$query->where("date >= DATE(?)", $params['fy']."-".$params['fm']."-".$params['fd']);
			$query->where("date <= DATE(?)", $params['ty']."-".$params['tm']."-".$params['td']);
	    }

        $query->where('quarantined=1');

        echo $query;
        $result = $query->query()->fetchAll();

        $elements = array();
        if ($limit && count($result) > $limit) {
        	return array('error' => 'LIMITREACHED');
        }
        foreach ($result as $c) {
        	foreach (STSoap_Content::$_fieldstosend as $f) {
        		$elements[$c['id']][$f] = utf8_encode($c[$f]);
			$elements[$c['id']][$f] = preg_replace('/[\x00-\x1F\x7F]/u', '', $elements[$c['id']][$f]);
        	}
        	#foreach (split('/\n/', $c['headers']) as $hl) {
        		#if (preg_match('/subject\s*:\s*(.*)/i', $hl, $matches)) {
        		#	$elements[$c['id']]['subject'] = utf8_encode($matches[1]);
        		#}
        	#}

        }

        return $elements;
	}


   /**
    * This function will fetch information on quarantined content
    *
    * @param  array  params
    * @return array
    */
	static public function Content_find($params) {
		$id = 0;
		if (isset($params['id'])) {
            $id = $params['id'];
		}
		if (!$id || !preg_match('/^(\d{8})\/([a-z,A-Z,0-9]{6}-[a-z,A-Z,0-9]{6,11}-[a-z,A-Z,0-9]{2,4})$/', $id, $matches)) {
			return array('status' => 0, 'error' => 'BADMSGID ('.$id.")");
		}
		$id = $matches[2];
		require_once('SpamTagger/Config.php');
    	$stconfig = SpamTagger_Config::getInstance();

    	require_once('Zend/Db/Adapter/Pdo/Mysql.php');
    	$contentDb = new Zend_Db_Adapter_Pdo_Mysql(array(
    	                      'host'        => 'localhost',
                              'unix_socket' => $stconfig->getOption('VARDIR')."/run/mariadb_replica/mariadbd.sock",
                              'username'    => 'spamtagger',
                              'password'    => $stconfig->getOption('MYSPAMTAGGERPWD'),
                              'dbname'      => 'st_stats'
                             ));
        $query = $contentDb->select();
        $query->from('maillog');

        $query->where('id = ?', $id);
        $result = $query->query()->fetch();
        if (!$result) {
        	return array('status' => 0, 'error' => 'MSGNOTFOUND'.$query);
        }
        $ret = array();
        foreach ($result as $key => $value) {
        	$ret[$key] = utf8_encode($value);
        }
	#foreach (split('/\n/', $result['headers']) as $hl) {
            #if (preg_match('/subject\s*:\s*(.*)/i', $hl, $matches)) {
            #	   $ret['subject'] = utf8_encode($matches[1]);
            #}
        #}

        $ret['status'] = 1;
        return $ret;
	}

   /**
    * This function will release a quarantined message
    *
    * @param  array  params
    * @return array
    */
	static public function Content_release($params) {
	    $id = 0;
		if (isset($params['id'])) {
            $id = $params['id'];
		}

		require_once('SpamTagger/Config.php');
		$stconfig = SpamTagger_Config::getInstance();
		$cmd = $stconfig->getOption('SRCDIR')."/bin/force_quarantined.pl ".$id;
		$res = `$cmd`;
		#$res = 'FORCED';
		$status = 0;
		if (preg_match('/^FORCED/', $res)) {
			$status = 1;
		}
		return array('status' => $status, 'message' => "$res", 'cmd' => "$cmd");
	}
}
