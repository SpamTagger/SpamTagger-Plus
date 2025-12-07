<?
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright 2025, SpamTagger
 */

 /**
  * SystemConfig contains the list of Slaves, and uses DataManager classes
  * It inherits from PrefHandler to manage preferences
  */
require_once ("system/Slave.php");
require_once ("helpers/DM_SlaveConfig.php");
require_once ("helpers/DM_MasterConfig.php");
require_once ("helpers/PrefHandler.php");

 /**
 * System configuration and global preferences
 * This class contains the global preferences and setting of the system
 * such as base paths, database access, etc...
 *
 * @package SpamTagger Plus
 * @todo set members as private !
 */

class SystemConfig extends PrefHandler {

  /**
   * Main spamtagger configuration file
   * This file contains the settings of the spamtagger configuration
   * @var $CONFIGFILE   string
   */
  public static $CONFIGFILE_ = '/etc/spamtagger.conf';
  /**
   * @todo these variables will have to be removed ! all classes should now use DataManager
   */
    private $dbhost_ = 'localhost';
    var $dbusername_ = 'spamtagger';
    var $dbconfig_ = 'st_config';
    var $dbspool_ = 'st_spool';
    var $dbstats_ = 'st_stats';
    var $dbpassword_ = '';

    /**
     * Path to the spamtagger installation directory
     * @var string
     */
    var $SRCDIR_ = '/usr/spamtagger';
    /**
     * Path to the spamtagger spool directory (given during installation process)
     * @var string
     */
    var $VARDIR_ = '/var/spamtagger';
    /**
     * Define if this host is a source or not
     * @var  number
     */
    var $issource_ = 0;

    /**
     * Instance of this singleton
     * @var SystemConfig
     */
     private static $instance_;

     /**
      * the main system preferences
      * @var  array
      */
     private $pref_ = array (
                    'organisation' => 'your_organisation',
                    'hostname' => 'spamtagger',
                    'hostid' => 1,
                    'clientid' => 0,
                    'default_domain' => 'your_domain',
                    'default_language' => 'en',
                    'sysadmin' => 'your_mail@yourdomain',
                    'days_to_keep_spams' => 60,
                    'days_to_keep_virus' => 60,
                    'cron_time' => '00:00:00',
                    'cron_weekday' => 1,
                    'cron_monthday' => 1,
                    'summary_subject' => '',
                    'analyse_to' => 'your_mail@yourdomain',
                    'summary_from' => 'your_mail@yourdomain',
                    'ad_server' => '',
                    'ad_param' => '',
                    'http_proxy' => '',
                    'smtp_proxy' => '',
                    'syslog_host' => '',
                    'falseneg_to' => '',
                    'falsepos_to' => ''
                  );

    /**
     * preferences of the user web interface
     * @var  array
     */
    var $gui_prefs_ = array (
                    'want_domainchooser' => 1,
                    'want_aliases' => 1,
                    'want_submit_analyse' => 1,
                    'want_reasons' => 1,
                    'want_force' => 1,
                    'want_display_user_infos' => 1,
                    'want_summary_select' => 1,
                    'want_delivery_select' => 1,
                    'want_support' => 1,
                    'want_preview' => 1,
                    'want_quarantine_bounces' => 1,
                    'default_quarantine_days' => 7,
                    'default_template' => 'default'
                  );

    /**
     * array of replicas. Key are replica name or ip, value is the Slave_ object
     * @var array
     */
    var $replicas_ = array ();
    /**
     * array of available user interface templates
     * @var array
     */
    var $web_templates_ = array ();
    /**
     * array of available templates for summaries
     * @var array
     */
    var $summary_templates_ = array ();
    /**
     * array of available templates for reports
     * @var array
     */
    var $report_templates_ = array ();

    /**
     * Constructor
     * This will load datas from the configuration file and the database
     */
    private function __construct() {
        require_once ('helpers/DataManager.php');
        $hostid = 0;

        $file_conf = DataManager :: getFileConfig(SystemConfig :: $CONFIGFILE_);

        foreach ($file_conf as $option => $value) {
            switch ($option) {
                case 'SRCDIR' :
                    $this->SRCDIR_ = $value;
                    break;
                case 'VARDIR' :
                    $this->VARDIR_ = $value;
                    break;
                case 'MYSPAMTAGGERPWD' :
                    $this->dbpassword_ = $value;
                    break;
                case 'ISMASTER' :
                    if ($value == "Y") {
                        $this->issource_ = 1;
                    }
                    break;
                case 'HOSTID' :
                    $hostid = $value;
                    break;
                default :
                    }
        }

        $this->addPrefSet('system_conf', 'c', $this->pref_);
        $this->addPrefSet('user_gui', 'u', $this->gui_prefs_);
        if (!$this->loadPrefs(null, null, false)) { return false; }
        $this->setPref('hostid', $hostid);
    }

    /**
     * Get the only one instance of this class
     * Get this singleton's instance
     * @return SystemConfig  this instance
     */
    public static function getInstance() {
        if (empty (self :: $instance_)) {
            self :: $instance_ = new SystemConfig();
        }
        return self :: $instance_;
    }

    /**
     * Load the configuration and preferences from the database
     * Get the configuration and the preferences of the system from the database
     * @return  bool  true on success, false on failure
     */
    private function loadFromDB() {
        $db_replicaconf = DM_SlaveConfig :: getInstance();
        $query = "SELECT ";
        foreach ($this->pref_ as $pref => $val) {
            $query .= $pref.", ";
        }
        $query = rtrim($query);
        $query = rtrim($query, '\,');
        $query .= " FROM system_conf";

        $res = $db_replicaconf->getHash($query);
        foreach ($res as $key => $value) {
            $this->setPref($key, $value);
        }
        return true;
    }

    /**
     * get the name of the domains actually filtered by the system
     * return the domain names filtered by the system, accordingly to the administrator rights
     * @return    array()  array of domain names
     * @todo cleanup $dom variable for sql injection
     */
    public function getFilteredDomains() {
        global $admin_;
        $domains = array ();

        $db_replicaconf = DM_SlaveConfig :: getInstance();

        $query = "SELECT name FROM domain WHERE (active='true' OR active=1) AND name != '__global__'";
        if (isset ($admin_) && $admin_->getPref('domains') != '*') {
            $query .= " AND (";
            foreach ($admin_->getDomains() as $dom) {
                $query .= " name='$dom' OR";
            }
            $query .= " 1=0 )";
        }

        $query .= " ORDER BY name";

        $domains = $db_replicaconf->getList($query);
        return $domains;
    }

    /**
     * Load the replica hosts configured for this system
     * Load the replica objects configured for this system
     * @return  bool    true on success, false on failure
     */
    public function loadSlaves() {

        $db_replicaconf = DM_SlaveConfig :: getInstance();

        $query = "SELECT id FROM replica ORDER BY id";
        $replicas = $db_replicaconf->getList($query);

        foreach ($replicas as $replica) {
            $this->replicas_[$replica] = new Slave();
            $this->replicas_[$replica]->load($replica);
        }
        return true;
    }

    /**
     * Dump a configuration file through all replicas
     * @param  $config   string   configuration to dump
     * @param  $params   string   command line parameters
     * @return           boolean  true on success, false on failures
     */
    public function dumpConfiguration($config, $params) {
    	if (count($this->replicas_) < 1) {
            $this->loadSlaves();
        }

        foreach ($this->replicas_ as $replica) {
        	if (!$replica->dumpConfiguration($config, $params)) {
        		return false;
        	}
        }

        return true;
    }

    /**
     * set a process as to be restarted
     * @param  $process string process to be restarted
     * @return          boolean true on success, false on failure
     */
    public function setProcessToBeRestarted($process) {
    	if (count($this->replicas_) < 1) {
            $this->loadSlaves();
        }

        foreach ($this->replicas_ as $replica) {
            if (!$replica->setProcessToBeRestarted($process)) {
                return false;
            }
        }
        return true;
    }
    /**
     * Get the replica hosts configured for this system
     * Get the replica objects configured for this system
     * @return array  array of Slaves_ objects
     */
    public function getSlaves() {
        if (count($this->replicas_) < 1) {
            $this->loadSlaves();
        }

        return $this->replicas_;
    }

    /**
     * get replica host name/ip from its id
     * @param  $replicaid  numeric replica id
     * @return           string  replica name or ip
     */
    public function getSlaveName($replicaid) {
        if (count($this->replicas_) < 1) {
            $this->loadSlaves();
        }
        if (!isset($this->replicas_[$replicaid])) {
          return "";
        }
        $replica = $this->replicas_[$replicaid];
        return $replica->getPref('hostname');
    }

    /**
     * Get the replica names or ip configured for this system
     * @return array array of name/ip (string)
     */
    public function getSlavesName() {
        $replicas = array ();
        if (count($this->replicas_) < 1) {
            $this->loadSlaves();
        }
        foreach ($this->replicas_ as $id => $host) {
            $replicas[$host->getPref('hostname')." ($id)"] = $host->getPref('hostname');
        }
        return $replicas;
    }

    /**
     * Get the source(s) name or ip configured fot this system
     * @return array array of name/ip (string)
     */
    public function getMastersName() {

        $db_replicaconf = DM_SlaveConfig :: getInstance();

        $sources = array ();
        $query = "SELECT hostname FROM source";
        $sources = $db_replicaconf->getList($query);
        foreach ($sources as $source) {
            $sources[$source] = $source;
        }

        return $sources;
    }

    /**
     * Get the replicas port, password and id as an array
     * @param  $replica  string  replica name
     * @return array array of array hosts information ((port, password, id))
     */
    public function getSlavePortPasswordID($replica) {
        if (count($this->replicas_) < 1) {
            $this->loadSlaves();
        }

        foreach ($this->replicas_ as $id => $s) {
            if ($s->getPref('hostname') == $replica) {
                return array ($s->getPref('port'), $s->getPref('password'), $s->getPref('id'));
            }
        }
        return array ('0', '', 0);
    }

    /**
     * Save system configuration and preferences to database
     * Save system configuration and preferences to database
     * @return         string  string 'OKSAVED' if successfully updated, 'OKADDED' id successfully added, error message if neither
     */
    public function save() {
        return $this->savePrefs(null, null, '');
    }

    /**
     * Set the system root password
     * @param $p  string  new password
     * @param $c  string  new password confirmation
     * @return    string  'OKSAVED' on success, error string on failure
     */
    public function setRootPassword($p, $c) {
        global $lang_;
        if (!isset ($p) || !isset ($c) || $p == "") {
            return $lang_->print_txt('NOPASSWORDORCONFIRMATIONGIVEN');
        }
        if ($p != $c) {
            return $lang_->print_txt('PASSWORDSDONOTMATCH');
        }
        $sudocmd = "/usr/bin/sudo";
        if (file_exists("/usr/sudo/bin/sudo")) {
          $sudocmd = "/usr/sudo/bin/sudo";
        }
        $cmd = "$sudocmd ".$this->SRCDIR_."/bin/setpassword root ".escapeshellarg($p);
        $res = array ();
        $res_a = array ();
        exec($cmd, $res_a, $res);
        if ($res != 0 || $res_a[3] != "passwd: password updated successfully") {
            return "ERRORINPASSWDCOMMAND - ".$res_a[3];
        }
        return "OKSAVED";
    }

    /**
     * Load the different templates available
     * Load the user web interface, summaries and reports templates available
     * @return  bool  true on success, false on failure
     */
    public function getTemplates() {
        $this->web_templates_ = array ();
        $this->summary_templates_ = array ();
        $this->report_templates_ = array ();
        $this->warnhit_templates_ = array ();

        $web_template_files = scandir($this->SRCDIR_."/www/user/htdocs/templates");
        $summary_template_files = scandir($this->SRCDIR_."/templates/summary");
        $report_template_files = scandir($this->SRCDIR_."/templates/reports");
        $warnhit_template_files = scandir($this->SRCDIR_."/templates/warnhit");

        foreach ($web_template_files as $template) {
            $tmp = array ();
            if (is_dir($this->SRCDIR_."/www/user/htdocs/templates/".$template) && $template != "CVS" && !preg_match('/^\./', $template, $tmp)) {
                $this->web_templates_[$template] = $template;
            }
        }

        foreach ($summary_template_files as $template) {
            if (is_dir($this->SRCDIR_."/templates/summary/".$template) && $template != "CVS" && !preg_match('/^\./', $template, $tmp)) {
                $this->summary_templates_[$template] = $template;
            }
        }

        foreach ($report_template_files as $template) {
            if (is_dir($this->SRCDIR_."/templates/reports/".$template) && $template != "CVS" && !preg_match('/^\./', $template, $tmp)) {
                $this->report_templates_[$template] = $template;
            }
        }
        foreach ($warnhit_template_files as $template) {
            if (is_dir($this->SRCDIR_."/templates/warnhit/".$template) && $template != "CVS" && !preg_match('/^\./', $template, $tmp)) {
                $this->warnhit_templates_[$template] = $template;
            }
        }
        return true;
    }

}
?>
