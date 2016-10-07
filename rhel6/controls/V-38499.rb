# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38499 - The /etc/passwd file must not contain password hashes.'

control 'V-38499' do
  impact 0.5
  title 'The /etc/passwd file must not contain password hashes.'
  desc '
The hashes for all user account passwords should be stored in the file "/etc/shadow" and never in "/etc/passwd", which is readable by all users.
'
  tag 'stig','V-38499'
  tag severity: 'medium'
  tag checkid: 'C-46056r1_chk'
  tag fixid: 'F-43446r1_fix'
  tag version: 'RHEL-06-000031'
  tag ruleid: 'SV-50300r1_rule'
  tag fixtext: '
If any password hashes are stored in "/etc/passwd" (in the second field, instead of an "x"), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely.
'
  tag checktext: '
To check that no password hashes are stored in "/etc/passwd", run the following command: 

# awk -F: \'($2 != "x") {print}\' /etc/passwd

If it produces any output, then a password hash is stored in "/etc/passwd". 
If any stored hashes are found in /etc/passwd, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
