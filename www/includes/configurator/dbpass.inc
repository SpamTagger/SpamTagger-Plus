<!--
#   SpamTagger Plus - Open Source Spam Filtering
#   Copyright (C) 2017 Florian Billebault <florian.billebault@gmail.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#
#   DB password change page of SpamTagger "Configurator" wizard
#
-->
<?php
if ('dbpass.inc' == basename($_SERVER['SCRIPT_FILENAME']))
  die ('Try again later.');
?>
	<h2 class="text-center">Step: <?php echo $validStep['title'] ?></h2>
	<p>This password will be set for mariadb root and spamtagger account.</p>
	<p class="text-danger">Please change this password only before setting a cluster. Otherwise, unset your cluster and reset it after this change.</p>
        <form class="form-horizontal" action="<?php echo $_SERVER['PHP_SELF']."?step=".$_GET['step']; ?>" method="post">
	  <div class="form-group">
	    <label class="col-md-5 control-label" for="oldpassdb">Old Password :</label>
	    <div class="col-md-4"><input type="password" id="autofill_<?php echo $_GET['step'] ?>" class="form-control col-md-6" name="oldpassdb" required placeholder="Password"></div>
        <button type="submit" name="autofill_<?php echo $_GET['step'] ?>" value="autofill" class="btn btn-default">Click here for default password</button>
	  </div>
      <div class="form-group">
	    <label class="col-md-5 control-label" for="newpassdb">New Password :</label>
	    <div class="col-md-4"><input type="password" class="form-control col-md-6" name="newpassdb" required pattern="[A-Za-z0-9]+" placeholder="A-Z a-z 0-9 only"></div>
	  </div>
	  <div class="form-group">
	    <label class="col-md-5 control-label" for="confnewpassdb">Re-type New Password :</label>
	    <div class="col-md-4"><input type="password" class="form-control col-md-6" name="confnewpassdb" required pattern="[A-Za-z0-9]+" placeholder="A-Z a-z 0-9 only"></div>
	  </div>
	  <div class="form-group">
	    <div class="col-md-offset-5 col-md-4">
	      <button type="submit" name="submit_<?php echo $_GET['step'] ?>" value="Submit" class="btn btn-default">Submit</button>
	    </div>
	  </div>
          <div class="form-group">
            <div class="col-md-offset-5 col-md-4">
            <?php
        if (isset($_POST['autofill_dbpass'])) {
          echo '<script type="text/javascript">document.getElementById("autofill_dbpass").value="'.'STPassw0rd'.'";</script>';
         }
         if (isset($_POST['submit_dbpass'])) {
  	      if (!empty($_POST['oldpassdb']) && !empty($_POST['newpassdb']) && !empty($_POST['confnewpassdb'])) {
	        if ($_POST['newpassdb'] == $_POST['confnewpassdb']) {
		require_once('db_functions.php');
		$source = getDb('', 'root', $_POST['oldpassdb']);
		$replica = getDb('', 'root', $_POST['oldpassdb'], false);
                if($source) {
		      $users = array("'spamtagger'@'%'", "'root'@'127.0.0.1'", "'root'@'::1'", "'root'@'spamtagger'", "'root'@'localhost'");

		      $sql = "SET PASSWORD FOR ".$users[0]." = PASSWORD(:newpassdb)";
		      $sth = $source->prepare($sql);
		      $retdb3 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
		      $sql = "SET PASSWORD FOR ".$users[0]." = PASSWORD(:newpassdb)";
                      $sth = $replica->prepare($sql);
                      $retdb4 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
		      exec("sudo /usr/spamtagger/scripts/configuration/set_pass_in_db.sh ".$_POST['newpassdb'], $outputdbconf, $retdbconf);
		      $sql = "SET PASSWORD FOR ".$users[1]." = PASSWORD(:newpassdb)";
                      $sth = $source->prepare($sql);
                      $retdb5 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
		      $sql = "SET PASSWORD FOR ".$users[2]." = PASSWORD(:newpassdb)";
                      $sth = $source->prepare($sql);
                      $retdb6 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
		      $sql = "SET PASSWORD FOR ".$users[3]." = PASSWORD(:newpassdb)";
                      $sth = $source->prepare($sql);
                      $retdb7 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
		      $sql = "SET PASSWORD FOR ".$users[1]." = PASSWORD(:newpassdb)";
                      $sth = $replica->prepare($sql);
                      $retdb8 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
		      $sql = "SET PASSWORD FOR ".$users[2]." = PASSWORD(:newpassdb)";
                      $sth = $replica->prepare($sql);
                      $retdb9 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
                      $sql = "SET PASSWORD FOR ".$users[3]." = PASSWORD(:newpassdb)";
                      $sth = $replica->prepare($sql);
                      $retdb10 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
		      $actual_hostid = shell_exec("grep HOSTID /etc/spamtagger.conf |cut -d' ' -f3");
                      $sth = $source->prepare("UPDATE st_config.source SET password=:newpassdb");
                      $retdbsource = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
                      $sth = $source->prepare("UPDATE st_config.replica SET password=:newpassdb where id=:hostid");
                      $retdbreplica = $sth->execute(array(':newpassdb' => $_POST['newpassdb'], ':hostid' => $actual_hostid)) == true ? 0 : 1;
		      $sql = "SET PASSWORD FOR ".$users[4]." = PASSWORD(:newpassdb)";
                      $sth = $source->prepare($sql);
		      $retdb1 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
                      $sql = "SET PASSWORD FOR ".$users[4]." = PASSWORD(:newpassdb)";
                      $sth = $replica->prepare($sql);
		      $retdb2 = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;

		      $sth = $replica->prepare("UPDATE st_config.source SET password=:newpassdb");
                      $retdbreplicasource = $sth->execute(array(':newpassdb' => $_POST['newpassdb'])) == true ? 0 : 1;
                      $sth = $replica->prepare("UPDATE st_config.replica SET password=:newpassdb where id=:hostid");
                      $retdbreplicareplica = $sth->execute(array(':newpassdb' => $_POST['newpassdb'], ':hostid' => $actual_hostid)) == true ? 0 : 1;

		      $sth = $replica->prepare("STOP REPLICA; CHANGE SOURCE TO SOURCE_PASSWORD=:sourcepass; START REPLICA;");
                      $retdbreplic = $sth->execute(array(':sourcepass' => $_POST['newpassdb'])) == true ? 0 : 1;

                      touch('/var/spamtagger/run/configurator/dbpass');
                } else {
                      $retdb1 = $retdbconf = $retdbreplic = $retdbsource = $retdbreplica = 1;
		      for($i = 1; $i <= 10; $i++)
			  ${'retdb' . $i} = 1;
                }

                ($retdb1 == 0) ? $retdb1 = "<span class='text-success'>Master instance Database root@localhost password changed</span>" : $retdb1 = "<span class='text-danger'>Failed to change Master instance Database root@localhost password</span>";
                ($retdb2 == 0) ? $retdb2 = "<span class='text-success'>Slave instance Database root@localhost password changed</span>" : $retdb2 = "<span class='text-danger'>Failed to change Slave instance Database root@localhost password</span>";
                ($retdb3 == 0) ? $retdb3 = "<span class='text-success'>Master instance Database spamtagger@% password changed</span>" : $retdb3 = "<span class='text-danger'>Failed to change Master instance Database spamtagger@% password</span>";
                ($retdb4 == 0) ? $retdb4 = "<span class='text-success'>Slave instance Database spamtagger@% password changed</span>" : $retdb4 = "<span class='text-danger'>Failed to change Slave instance Database spamtagger@% password</span>";
                ($retdb5 == 0) ? $retdb5 = "<span class='text-success'>Master instance Database root@127.0.0.1 password changed</span>" : $retdb5 = "<span class='text-danger'>Failed to change Master instance Database root@127.0.0.1 password</span>";
                ($retdb6 == 0) ? $retdb6 = "<span class='text-success'>Master instance Database root@::1 password changed</span>" : $retdb6 = "<span class='text-danger'>Failed to change Master instance Database root@::1 password</span>";
                ($retdb7 == 0) ? $retdb7 = "<span class='text-success'>Master instance Database root@spamtagger password changed</span>" : $retdb7 = "<span class='text-danger'>Failed to change Master instance Database root@spamtagger password</span>";
                ($retdb8 == 0) ? $retdb8 = "<span class='text-success'>Slave instance Database root@127.0.0.1 password changed</span>" : $retdb8 = "<span class='text-danger'>Failed to change Slave instance Database root@127.0.0.1 password</span>";
                ($retdb9 == 0) ? $retdb9 = "<span class='text-success'>Slave instance Database root@::1 password changed</span>" : $retdb9 = "<span class='text-danger'>Failed to change Slave instance Database root@::1 password</span>";
                ($retdb10 == 0) ? $retdb10 = "<span class='text-success'>Slave instance Database root@spamtagger password changed</span>" : $retdb10 = "<span class='text-danger'>Failed to change Slave instance Database root@spamtagger password</span>";
                ($retdbconf == 0) ? $retdbconf = "<span class='text-success'>Master and Slave instance Database passwords changed in configuration</span>" : $retdbconf = "<span class='text-danger'>Failed to change Master and Slave instance Database password in conf</span>";
                ($retdbreplic == 0) ? $retdbreplic = "<span class='text-success'>Mysql Replication password changed</span>" : $retdbreplic = "<span class='text-danger'>Failed to change Mysql Replication password</span>";
                ($retdbsource == 0) ? $retdbsource = "<span class='text-success'>Mysql password changed in table source on instance source</span>" : $retdbsource = "<span class='text-danger'>Failed to change Mysql password in table source on instance source</span>";
                ($retdbreplicasource == 0) ? $retdbreplicasource = "<span class='text-success'>Mysql password changed in table source on instance replica</span>" : $retdbreplicasource = "<span class='text-danger'>Failed to change Mysql password in table source on instance replica</span>";
                ($retdbreplica == 0) ? $retdbreplica = "<span class='text-success'>Mysql password changed in table replica on instance source</span>" : $retdbreplica = "<span class='text-danger'>Failed to change Mysql password in table replica on instance source</span>";
                ($retdbreplicareplica == 0) ? $retdbreplicareplica = "<span class='text-success'>Mysql password changed in table replica on instance replica</span>" : $retdbreplicareplica = "<span class='text-danger'>Failed to change Mysql password in table replica on instance replica</span>";
                echo $retdb1;
                echo "<br/>";
                echo $retdb2;
         	echo "<br/>";
		echo $retdb3;
                echo "<br/>";
                echo $retdb4;
                echo "<br/>";
                echo $retdb5;
                echo "<br/>";
                echo $retdb6;
                echo "<br/>";
                echo $retdb7;
                echo "<br/>";
                echo $retdb8;
                echo "<br/>";
                echo $retdb9;
                echo "<br/>";
                echo $retdb10;
                echo "<br/>";
                echo $retdbconf;
                echo "<br/>";
                echo $retdbreplic;
                echo "<br/>";
                echo $retdbsource;
                echo "<br/>";
                echo $retdbreplica;
		echo "<br/>";
                echo $retdbreplicasource;
                echo "<br/>";
                echo $retdbreplicareplica;
		} else {
	          echo "<span class='text-danger'>New Password and Re-type Password field have to be identical !</span>";
	        }
	      } else {
	        echo "<span class='text-danger'>No field should stay empty !</span>";
	      }
	    }
           ?>
           </div>
         </div>
	</form>
