use st_config;

DROP TABLE IF EXISTS rrd_stats_element;

CREATE TABLE rrd_stats_element (
  id			int(11) AUTO_INCREMENT NOT NULL,
  stats_id      int(11) NOT NULL,
  name          varchar(255),
  type          enum('GAUGE','COUNTER','DERIVE','ABSOLUTE','COMPUTE') DEFAULT 'COUNTER',
  function      enum('AVERAGE','MIN','MAX','LAST') DEFAULT 'AVERAGE',
  oid           varchar(255),
  min           varchar(255) DEFAULT 'U',
  max           varchar(255) DEFAULT 'U',
  draw_name     varchar(255),
  draw_order    int(11) NOT NULL DEFAULT 1,
  draw_style    enum('line','area','stack') DEFAULT 'line',
  draw_factor   varchar(255) DEFAULT '',
  draw_format   varchar(255) DEFAULT '8.0lf',
  draw_unit     varchar(255) DEFAULT '',
  PRIMARY KEY (id)
);

## global                      
INSERT INTO rrd_stats_element VALUES(NULL, 1, 'countspams', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedCount + SPAMTAGGER-MIB::globalSpamCount','0','U', 'spams',2,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 1, 'countdangerous', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalVirusCount + SPAMTAGGER-MIB::globalNameCount + SPAMTAGGER-MIB::globalOtherCount','0','U', 'dangerous',1,'area','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 1, 'countoutgoing', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedCount','0','U', 'outgoing',3,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 1, 'countcleans', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalCleanCount','0','U', 'cleans',4,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 2, 'spams', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedCount + SPAMTAGGER-MIB::globalSpamCount','0','10000', 'spams',1,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 2, 'dangerous', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalVirusCount + SPAMTAGGER-MIB::globalNameCount + SPAMTAGGER-MIB::globalOtherCount','0','10000', 'dangerous',2,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 2, 'outgoing', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedCount','0','10000', 'outgoing',3,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 2, 'cleans', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalCleanCount','0','10000', 'cleans',4,'line','','8.2lf','');


## sessions                               
INSERT INTO rrd_stats_element VALUES(NULL, 3, 'countaccepted', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalMsgCount','0','U', 'accepted',3,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 3, 'countrefused', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedCount','0','U', 'refused',1,'area','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 3, 'countdelayed', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalDelayedCount','0','U', 'delayed',2,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 3, 'countrelayed', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedCount','0','U', 'relayed',4,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 4, 'accepted', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalMsgCount','0','10000', 'accepted',1,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 4, 'refused', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedCount','0','10000', 'refused',2,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 4, 'delayed', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalDelayedCount','0','10000', 'delayed',3,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 4, 'relayed', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedCount','0','10000', 'relayed',4,'line','','8.2lf','');

## accepted                    
INSERT INTO rrd_stats_element VALUES(NULL, 5, 'countcleans', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalCleanCount','0','U', 'cleans',3,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 5, 'countspams', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalSpamCount','0','U', 'spams',2,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 5, 'countdangerous', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalVirusCount + SPAMTAGGER-MIB::globalNameCount + SPAMTAGGER-MIB::globalOtherCount','0','U', 'dangerous',1,'area','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 6, 'cleans', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalCleanCount','0','10000', 'cleans',1,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 6, 'spams', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalSpamCount','0','10000', 'spams',2,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 6, 'dangerous', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalVirusCount + SPAMTAGGER-MIB::globalNameCount + SPAMTAGGER-MIB::globalOtherCount','0','10000', 'dangerous',3,'line','','8.2lf','');


## refused
INSERT INTO rrd_stats_element VALUES(NULL, 7, 'countrbl', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedRBLCount + SPAMTAGGER-MIB::globalRefusedBackscatterCount','0','U', 'rbl',1,'area','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 7, 'countblacklists', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedHostCount + SPAMTAGGER-MIB::globalRefusedBlacklistedSenderCount','0','U', 'blacklists',2,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 7, 'countrelay', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedRelayCount','0','U', 'relay',3,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 7, 'countpolicies', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedBATVCount + SPAMTAGGER-MIB::globalRefusedBadSPFCount + SPAMTAGGER-MIB::globalRefusedSpoofingCount + SPAMTAGGER-MIB::globalRefusedUnauthenticatedCount + SPAMTAGGER-MIB::globalRefusedUnencryptedCount','0','U', 'policies',4,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 7, 'countcallout', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedCalloutCount','0','U', 'callout',5,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 7, 'countsyntax', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedLocalpartCount + SPAMTAGGER-MIB::globalRefusedBadSenderCount + SPAMTAGGER-MIB::globalRefusedBadSenderCount','0','U', 'syntax',6,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 8, 'rbl', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedRBLCount + SPAMTAGGER-MIB::globalRefusedBackscatterCount','0','10000', 'rbl',1,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 8, 'blacklists', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedHostCount + SPAMTAGGER-MIB::globalRefusedBlacklistedSenderCount','0','10000', 'blacklists',2,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 8, 'relay', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedRelayCount','0','10000', 'relay',3,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 8, 'policies', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedBATVCount + SPAMTAGGER-MIB::globalRefusedBadSPFCount + SPAMTAGGER-MIB::globalRefusedSpoofingCount + SPAMTAGGER-MIB::globalRefusedUnauthenticatedCount + SPAMTAGGER-MIB::globalRefusedUnencryptedCount','0','10000', 'policies',4,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 8, 'callout', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedCalloutCount','0','10000', 'callout',5,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 8, 'syntax', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRefusedLocalpartCount + SPAMTAGGER-MIB::globalRefusedBadSenderCount + SPAMTAGGER-MIB::globalRefusedBadSenderCount','0','10000', 'syntax',6,'line','','8.2lf','');


## delayed
INSERT INTO rrd_stats_element VALUES(NULL, 9, 'countgreylisted', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalDelayedGreylistCount','0','U', 'greylisted',1,'area','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 9, 'countratelimited', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalDelayedRatelimitCount','0','U', 'rate limited',2,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 10, 'greylisted', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalDelayedGreylistCount','0','10000', 'greylisted',1,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 10, 'ratelimited', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalDelayedRatelimitCount','0','10000', 'rate limited',2,'line','','8.2lf','');

## relayed                               
INSERT INTO rrd_stats_element VALUES(NULL, 11, 'countbyhosts', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedHostCount','0','U', 'by hosts',3,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 11, 'countauthentified', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedAuthenticatedCount','0','U', 'authentified',4,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 11, 'countrefused', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedRefusedCount','0','U', 'refused',2,'stack','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 11, 'countvirus', 'GAUGE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedVirusCount','0','U', 'virus',1,'area','','12.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 12, 'byhosts', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedHostCount','0','10000', 'by hosts',1,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 12, 'authentified', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedAuthenticatedCount','0','10000', 'authentified',2,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 12, 'refused', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedRefusedCount','0','10000', 'refused',3,'line','','8.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 12, 'virus', 'DERIVE', 'LAST', 'SPAMTAGGER-MIB::globalRelayedVirusCount','0','10000', 'virus',4,'line','','8.2lf','');

## system graphs

# load
INSERT INTO rrd_stats_element VALUES(NULL, 13, 'load1', 'GAUGE', 'AVERAGE', 'UCD-SNMP-MIB::laLoad.1','0','500', 'load1',1,'area','','4.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 13, 'load5', 'GAUGE', 'AVERAGE', 'UCD-SNMP-MIB::laLoad.2','0','500', 'load5',2,'stack','','4.2lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 13, 'load15', 'GAUGE', 'AVERAGE', 'UCD-SNMP-MIB::laLoad.3','0','500', 'load15',3,'stack','','4.2lf','');

# disk usage
INSERT INTO rrd_stats_element VALUES(NULL, 14, 'system', 'GAUGE', 'LAST', 'UCD-SNMP-MIB::dskPercent.__OS_USAGE__','0','100', 'system',2,'line','','10.0lf','%%');
INSERT INTO rrd_stats_element VALUES(NULL, 14, 'data', 'GAUGE', 'LAST', 'UCD-SNMP-MIB::dskPercent.__DATA_USAGE__','0','100', 'data',1,'area','','10.0lf','%%');
# memory usage
INSERT INTO rrd_stats_element VALUES(NULL, 15, 'used', 'GAUGE', 'LAST', 'UCD-SNMP-MIB::memTotalReal.0 - UCD-SNMP-MIB::memAvailReal.0','0','U', 'used',1,'area','*1024','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 15, 'free', 'GAUGE', 'LAST', 'UCD-SNMP-MIB::memAvailReal.0','0','U', 'free',2,'stack','*1024','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 15, 'cached', 'GAUGE', 'LAST', 'UCD-SNMP-MIB::memCached.0','0','U', 'cached',3,'area','*1024','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 15, 'buffered', 'GAUGE', 'LAST', 'UCD-SNMP-MIB::memBuffer.0','0','U', 'buffered',4,'stack','*1024','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 15, 'swap', 'GAUGE', 'LAST', 'UCD-SNMP-MIB::memTotalSwap.0 - UCD-SNMP-MIB::memAvailSwap.0','0','U', 'swap',5,'line','*1024','8.2lf','%s');
# spools status
INSERT INTO rrd_stats_element VALUES(NULL, 16, 'spool_incoming', 'GAUGE', 'AVERAGE', 'SPAMTAGGER-MIB::spoolIncoming','0','U', 'incoming_spool',1,'line','','8.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 16, 'spool_filtering', 'GAUGE', 'AVERAGE', 'SPAMTAGGER-MIB::spoolFiltering','0','U', 'filtering_spool',2,'line','','8.0lf','');
INSERT INTO rrd_stats_element VALUES(NULL, 16, 'spool_outgoing', 'GAUGE', 'AVERAGE', 'SPAMTAGGER-MIB::spoolOutgoing','0','U', 'outgoing_spool',3,'line','','8.0lf','');
# cpu utilization
INSERT INTO rrd_stats_element VALUES(NULL, 17, 'cpu_system', 'COUNTER', 'AVERAGE', 'UCD-SNMP-MIB::ssCpuRawSystem.0','0','10000', 'system',1,'area','','8.2lf','%%');
INSERT INTO rrd_stats_element VALUES(NULL, 17, 'cpu_wait', 'COUNTER', 'AVERAGE', 'UCD-SNMP-MIB::ssCpuRawWait.0','0','10000', 'wait',2,'stack','','8.2lf','%%');
INSERT INTO rrd_stats_element VALUES(NULL, 17, 'cpu_user', 'COUNTER', 'AVERAGE', 'UCD-SNMP-MIB::ssCpuRawUser.0','0','10000', 'user',3,'stack','','8.2lf','%%');
INSERT INTO rrd_stats_element VALUES(NULL, 17, 'cpu_nice', 'COUNTER', 'AVERAGE', 'UCD-SNMP-MIB::ssCpuRawNice.0','0','10000', 'nice',4,'stack','','8.2lf','%%');
INSERT INTO rrd_stats_element VALUES(NULL, 17, 'cpu_idle', 'COUNTER', 'AVERAGE', 'UCD-SNMP-MIB::ssCpuRawIdle.0','0','10000', 'idle',5,'stack','','8.2lf','%%');
# disk IO
INSERT INTO rrd_stats_element VALUES(NULL, 18, 'io_write_os', 'COUNTER', 'AVERAGE', 'UCD-DISKIO-MIB::diskIONWritten.__OS_IO__','0','U', 'write_os',1,'line','','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 18, 'io_read_os', 'COUNTER', 'AVERAGE', 'UCD-DISKIO-MIB::diskIONRead.__OS_IO__','0','U', 'read_os',2,'line','','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 18, 'io_write_data', 'COUNTER', 'AVERAGE', 'UCD-DISKIO-MIB::diskIONWritten.__DATA_IO__','0','U', 'write_data',3,'line','','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 18, 'io_read_data', 'COUNTER', 'AVERAGE', 'UCD-DISKIO-MIB::diskIONRead.__DATA_IO__','0','U', 'read_data',4,'line','','8.2lf','%s');
# network bandwidth
INSERT INTO rrd_stats_element VALUES(NULL, 19, 'network_if_in', 'COUNTER', 'AVERAGE', 'IF-MIB::ifInOctets.__IF__','0','U', 'if_in',1,'area','*8','8.2lf','%s');
INSERT INTO rrd_stats_element VALUES(NULL, 19, 'network_if_out', 'COUNTER', 'AVERAGE', 'IF-MIB::ifOutOctets.__IF__','0','U', 'if_out',2,'line','*8','8.2lf','%s');
