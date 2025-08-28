USE st_config;
DROP TABLE IF EXISTS external_access;

CREATE TABLE external_access (
  id         int(11) NOT NULL AUTO_INCREMENT,
  service    varchar(20) NOT NULL,
  port       varchar(20),
  protocol   enum('TCP', 'UDP', 'ICMP'),
  allowed_ip blob,
  auth       blob,
  PRIMARY KEY (id)
);

INSERT INTO external_access SET service='web', port='80:443', protocol='TCP', allowed_ip='0.0.0.0/0';
INSERT INTO external_access SET service='mysql', port='3306:3307', protocol='TCP', allowed_ip='127.0.0.1';
INSERT INTO external_access SET service='snmp', port='161', protocol='UDP', allowed_ip='127.0.0.1', auth='spamtagger';
INSERT INTO external_access SET service='ssh', port='22', protocol='TCP', allowed_ip='0.0.0.0/0';
INSERT INTO external_access SET service='mail', port='25', protocol='TCP', allowed_ip='0.0.0.0/0';
