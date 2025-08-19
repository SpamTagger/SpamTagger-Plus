<?php
/**
 * @license https://www.gnu.org/licenses/gpl-3.0.en.html
 * @package SpamTagger Plus
 * @author Olivier Diserens
 * @copyright (C) 2004-2014 Olivier Diserens <olivier@diserens.ch>
 *                2015-2017 Mentor Reka <reka.mentor@gmail.com>
 *                2015-2017 Florian Billebault <florian.billebault@gmail.com>
 */
class STSoap_Config
{

  /**
   * This function simply copy temporary interfaces file to system one
   *
   * @return string
   */
	static public function Config_saveInterfaceConfig() {
		$tmpfile = "/tmp/st_initerfaces.tmp";

		if (!file_exists($tmpfile)) {
			return 'NOK notempfile';
		}
		$cmd = "/bin/cp $tmpfile /etc/network/interfaces";
		$res = `$cmd`;
		if ($res == "") {
			return 'OK settingsaved';
		} else {
			return 'NOK '.$res;
		}
   }

   /**
   * This function restart networking services
   *
   * @return string
   */
   static public function Config_applyNetworkSettings() {

          ## first check run directory
          $rundir = "/etc/network/run";
          if (is_link ($rundir) || is_file($rundir) ) {
              unlink($rundir);
          }
          if (!is_dir ($rundir) ) {
              mkdir($rundir);
          }

      ## shut down all existing interfaces
      $ifconfig = `/sbin/ifconfig`;
      foreach (preg_split("/\n/", $ifconfig) as $line) {
      	 if (preg_match('/^(\S+)/', $line, $matches)) {
      	 	 $ifname = $matches[1];
      	 	 if ($ifname == 'lo') {
      	 	 	continue;
      	 	 }
      	     $resetcmd = "/sbin/ifconfig 0.0.0.0 ".$ifname;
             $resetres = `$resetcmd >/dev/null 2>&1`;
             $downcmd = "/sbin/ifconfig ".$ifname." down";
             $downres = `$downcmd >/dev/null 2>&1`;
             echo $downcmd."<br />";
          }
      }

#      $cmd = 'invoke-rc.d networking stop 2> /dev/null; sleep 2; invoke-rc.d networking start 2> /dev/null && /etc/init.d/ssh restart 2> /dev/null && echo done.';
      $cmd = '/etc/init.d/networking restart 2>/dev/null && /etc/init.d/ssh restart 2> /dev/null && echo done.';
      $res = `$cmd`;
      $status = 'OK networkingrestarted';

      $res = preg_replace('/\n/', '', $res);
   	  if (! preg_match('/done\./', $res)) {
   	  	return "NOK $res";
   	  }

   	  require_once('NetworkInterface.php');
   	  require_once('NetworkInterfaceMapper.php');
   	  $ifs = new Default_Model_NetworkInterface();
   	  foreach ($ifs->fetchAll() as $i) {
   	  	if ($i->getIPv4Param('mode') != 'disabled' || $i->getIPv6Param('mode') != 'disabled') {
   	  		$upcmd = "/sbin/ifconfig ".$i->getName()." up";
   	  		$upres = `$upcmd >/dev/null 2>&1`;
   	  	}
   	  }

          require_once('SpamTagger/Config.php');
          $sysconf = SpamTagger_Config::getInstance();
          $cmd = $sysconf->getOption('SRCDIR')."/etc/init.d/firewall restart";
          `$cmd >/dev/null 2>&1`;
   	  return $status;
   }


  /**
   * This function simply copy temporary resolv.conf file to system one
   *
   * @return string
   */
	static public function Config_saveDnsConfig() {
		$tmpfile = "/tmp/st_resolv.tmp";
		$status = 'OK';

		if (!file_exists($tmpfile)) {
			return 'NOK notempfile';
		}
		$cmd = "/bin/cp $tmpfile /etc/resolv.conf";
		$res = `$cmd`;
		if ($res == "") {
			$status = 'OK settingsaved';
		} else {
			$status = 'NOK '.$res;
		}

		if (file_exists('/etc/init.d/nscd')) {
			$cmd = '/etc/init.d/nscd restart';
			$res = `$cmd`;
			$res = preg_replace('/\n/', '', $res);
   	        if (! preg_match('/nscd\./', $res)) {
   	            return "NOK $res";
   	        } else {
		        $status = 'OK settingapplied';
   	        }
		}

		return $status;
   }

   /**
   * This function set up the time zone
   *
   * @return string
   */
	static public function Config_saveTimeZone($zone) {
	    $timezonefile = '/etc/timezone';
	    $zoneinfodir = '/usr/share/zoneinfo';
	    $localtimefile = '/etc/localtime';

	    $data = preg_split('/\//', $zone);
	    if (!isset($data[0]) || !isset($data[1])) {
	    	return 'NOK bad locale format';
	    }

        $fullfile = $zoneinfodir."/".$data[0]."/".$data[1];
        if (! file_exists($fullfile)) {
        	return 'NOK unknown locale ';
        }

	    $written = file_put_contents($timezonefile, $zone);
	    if (!$written) {
	    	return 'NOK could not same timezone';
	    }

            unlink($localtimefile);
            `ln -s $fullfile $localtimefile`;
	    putenv("TZ=".$zone);
           # `/usr/spamtagger/etc/init.d/apache restart`;
             return 'OK saved';
	}


  /**
   * This function apply the ntp config
   *
   * @param  boolean  sync
   * @return string
   */
	static public function Config_saveNTPConfig($sync = false) {
		$tmpconfigfile = '/tmp/st_ntp.tmp';
		$configfile = '/etc/ntp.conf';
		$starter = '/etc/init.d/ntp';
        $full = '';

	        if (is_array($sync) && defined($sync['sync'])) {
                  $sync = $sync['sync'];
                }
	    if (! file_exists($tmpconfigfile)) {
			return 'NOK notempfile';
		}
		$cmd = "/bin/cp $tmpconfigfile $configfile";
		$res = `$cmd`;
		$full .= preg_replace('/\n/', '', $res)."<br />";
		if ($res == "") {
		    $status = 'OK settingsaved';
		} else {
		    $status = 'NOK '.$res;
		}


		if (file_exists($starter)) {
		    $cmd = "$starter stop";
		    $res = `$cmd`;
            $full .= preg_replace('/\n/', '', $res)."<br />";
            # typical command output:
            # "Stopping ntp (via systemctl): ntp.service"
		    if (!preg_match('/ntp/', $res)) {
		    	return 'NOK cannotstopntp ';
		    }

		    if ($sync) {
		    	# fetch server to sync
		    	$content = file($configfile);
		    	$servers = array();
		    	foreach ($content as $line) {
		    		if (preg_match('/^\s*server\s+(\S+)/', $line, $matches)) {
		    			$servers[] = $matches[1];
		    		}
		    	}
		    	if (count($servers) < 1) {
		    		return 'NOK not server to sync with';
		    	}

			    $cmd = '/usr/sbin/ntpdate '.$servers[0]." 2>&1";
			    $res = `$cmd`;
		        $full .= preg_replace('/\n/', '', $res)."<br />";
			    	$res2 = preg_replace('/\n/', '', $res);
			    if (!preg_match('/offset/', $res)) {
			    	$res = preg_replace('/\n/', '', $res);
			    	return "NOK could not sync <br />($res)";
			    }

		        $cmd = "$starter start";
		        $res = `$cmd`;
		        $full .= preg_replace('/\n/', '', $res)."<br />";
		        if (!preg_match('/ntp/', $res)) {
		    	    return 'NOK cannotstartntp ';
		        }
		        return 'OK ntp started and synced';
		    }
		    return 'OK ntp disabled';
		} else {
		    if ($sync) {
                return 'NOK nontpclient';
			}
		}
		return 'OK saved';
	}


  /**
   * This function apply the provided time and date
   *
   * @param  string  date and time
   * @return string
   */
	static public function Config_saveDateTime($string) {
		$cmd = '/bin/date '.escapeshellcmd($string);
		$res = `$cmd`;
		$res = preg_replace('/\n/', '', $res);
		return 'OK saved';
	}

  /**
   * This function will save some SpamTagger config option
   *
   * @param  array  options
   * @return string
   */
	static public function Config_saveSTConfigOption($options) {
		$configfile = '/etc/spamtagger.conf';

		$txt = '';
		$found = array();
		if (file_exists($configfile)) {
			$content = file($configfile);
			foreach ($content as $line) {
				foreach ($options as $okey => $oval) {
					if (preg_match("/^\s*".$okey."\s*=/", $line, $matches)) {
						$line = $okey." = ".$oval."\n";
						$found[$okey] = 1;
					}
				}
			    $txt .= $line;
			}
		}
		foreach ($options as $okey => $oval) {
			if (!isset($found[$okey])) {
				$txt .= $okey." = ".$oval."\n";
			}
		}

	    $written = file_put_contents($configfile, $txt);
	    if (!$written) {
	    	return 'NOK could not same config file';
	    }
	    return 'OK saved';
	}

	 /**
        * This function will set the host id
        *
        * @param  array of data for changing the host id
        * @return string
        */
	static public function Config_hostid($data) {
                require_once('SpamTagger/Config.php');
                $sysconf = SpamTagger_Config::getInstance();

                if (!isset($data['host_id']) || !preg_match('/^\d+$/', $data['host_id'])) {
                        return "NOK You have to specify an integer for host_id";
		}

                $cmd = $sysconf->getOption('SRCDIR')."/bin/change_hostid.sh ".$data['host_id']." -f";
                $res = `$cmd`;
                if (preg_match('/SUCCESS/', $res)) {
                   return 'OK registered '.$res;
                }
                return 'NOK '.$res;
        }

}
