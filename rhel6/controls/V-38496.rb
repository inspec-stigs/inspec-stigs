# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38496 - Default operating system accounts, other than root, must be locked.'

control 'V-38496' do
  impact 0.5
  title 'Default operating system accounts, other than root, must be locked.'
  desc '
Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system.
'
  tag 'stig','V-38496'
  tag severity: 'medium'
  tag checkid: 'C-46052r2_chk'
  tag fixid: 'F-43442r2_fix'
  tag version: 'RHEL-06-000029'
  tag ruleid: 'SV-50297r3_rule'
  tag fixtext: '
Some accounts are not associated with a human user of the system, and exist to perform some administrative function. An attacker should not be able to log into these accounts. 

Disable logon access to these accounts with the command: 

# passwd -l [SYSACCT]
'
  tag checktext: '
To obtain a listing of all users and the contents of their shadow password field, run the command: 

$ awk -F: \'$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 ":" $2}\' /etc/shadow

Identify the operating system accounts from this listing. These will primarily be the accounts with UID numbers less than 500, other than root. 

If any default operating system account (other than root) has a valid password hash, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
