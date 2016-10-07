# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38616 - The SSH daemon must not permit user environment settings.'

control 'V-38616' do
  impact 0.1
  title 'The SSH daemon must not permit user environment settings.'
  desc '
SSH environment options potentially allow users to bypass access restriction in some configurations.
'
  tag 'stig','V-38616'
  tag severity: 'low'
  tag checkid: 'C-46175r1_chk'
  tag fixid: 'F-43565r1_fix'
  tag version: 'RHEL-06-000241'
  tag ruleid: 'SV-50417r1_rule'
  tag fixtext: '
To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in "/etc/ssh/sshd_config": 

PermitUserEnvironment no
'
  tag checktext: '
To ensure users are not able to present environment daemons, run the following command: 

# grep PermitUserEnvironment /etc/ssh/sshd_config

If properly configured, output should be: 

PermitUserEnvironment no


If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
