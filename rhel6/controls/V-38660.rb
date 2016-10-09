# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38660 - The snmpd service must use only SNMP protocol version 3 or newer.'

control 'V-38660' do
  impact 0.5
  title 'The snmpd service must use only SNMP protocol version 3 or newer.'
  desc '
Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information.

'
  tag 'stig','V-38660'
  tag severity: 'medium'
  tag checkid: 'C-46215r1_chk'
  tag fixid: 'F-43604r1_fix'
  tag version: 'RHEL-06-000340'
  tag ruleid: 'SV-50461r1_rule'
  tag fixtext: '
Edit "/etc/snmp/snmpd.conf", removing any references to "v1", "v2c", or "com2sec". Upon doing that, restart the SNMP service:

# service snmpd restart
'
  tag checktext: '
To ensure only SNMPv3 or newer is used, run the following command:

# grep \'v1\|v2c\|com2sec\' /etc/snmp/snmpd.conf | grep -v \'^#\'

There should be no output.
If there is output, this is a finding.
'

# START_DESCRIBE V-38660
  tag 'snmp','snmpd.conf'
  only_if { file('/etc/snmp/snmpd.conf').exist? }
  describe command("grep 'v1\\|v2c\\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'") do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38660

end
