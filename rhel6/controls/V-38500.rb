# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38500 - The root account must be the only account having a UID of 0.'

control 'V-38500' do
  impact 0.5
  title 'The root account must be the only account having a UID of 0.'
  desc '
An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.
'
  tag 'stig','V-38500'
  tag severity: 'medium'
  tag checkid: 'C-46057r2_chk'
  tag fixid: 'F-43447r1_fix'
  tag version: 'RHEL-06-000032'
  tag ruleid: 'SV-50301r2_rule'
  tag fixtext: '
If any account other than root has a UID of 0, this misconfiguration should be investigated and the accounts other than root should be removed or have their UID changed.
'
  tag checktext: '
To list all password file entries for accounts with UID 0, run the following command: 

# awk -F: \'($3 == 0) {print}\' /etc/passwd

This should print only one line, for the user root. 
If any account other than root has a UID of 0, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
