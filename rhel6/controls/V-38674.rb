# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38674 - X Windows must not be enabled unless required.'

control 'V-38674' do
  impact 0.5
  title 'X Windows must not be enabled unless required.'
  desc '
Unnecessary services should be disabled to decrease the attack surface of the system.
'
  tag 'stig','V-38674'
  tag severity: 'medium'
  tag checkid: 'C-46234r1_chk'
  tag fixid: 'F-43623r1_fix'
  tag version: 'RHEL-06-000290'
  tag ruleid: 'SV-50475r1_rule'
  tag fixtext: '
Setting the system\'s runlevel to 3 will prevent automatic startup of the X server. To do so, ensure the following line in "/etc/inittab" features a "3" as shown: 

id:3:initdefault:
'
  tag checktext: '
To verify the default runlevel is 3, run the following command: 

# grep initdefault /etc/inittab

The output should show the following: 

id:3:initdefault:


If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
