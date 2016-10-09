# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38653 - The snmpd service must not use a default password.'

control 'V-38653' do
  impact 1.0
  title 'The snmpd service must not use a default password.'
  desc '
Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system.
'
  tag 'stig','V-38653'
  tag severity: 'high'
  tag checkid: 'C-46213r1_chk'
  tag fixid: 'F-43602r1_fix'
  tag version: 'RHEL-06-000341'
  tag ruleid: 'SV-50454r1_rule'
  tag fixtext: '
Edit "/etc/snmp/snmpd.conf", remove default community string "public". Upon doing that, restart the SNMP service:

# service snmpd restart
'
  tag checktext: '
To ensure the default password is not set, run the following command:

# grep -v "^#" /etc/snmp/snmpd.conf| grep public

There should be no output.
If there is output, this is a finding.
'

# START_DESCRIBE V-38653
  tag 'snmp','snmpd.conf'
  only_if { file('/etc/snmp/snmpd.conf').exist? }
  describe command('grep -v "^#" /etc/snmp/snmpd.conf| grep public') do
    its('stdout') { should eq '' }
  end
# END_DESCRIBE V-38653

end
