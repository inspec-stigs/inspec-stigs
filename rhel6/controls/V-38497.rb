# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38497 - The system must not have accounts configured with blank or null passwords.'

control 'V-38497' do
  impact 1.0
  title 'The system must not have accounts configured with blank or null passwords.'
  desc '
If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.
'
  tag 'stig','V-38497'
  tag severity: 'high'
  tag checkid: 'C-46054r2_chk'
  tag fixid: 'F-43444r4_fix'
  tag version: 'RHEL-06-000030'
  tag ruleid: 'SV-50298r2_rule'
  tag fixtext: '
If an account is configured for password authentication but does not have an assigned password, it may be possible to log onto the account without authentication. Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" to prevent logons with empty passwords.
'
  tag checktext: '
To verify that null passwords cannot be used, run the following command: 

# grep nullok /etc/pam.d/system-auth

If this produces any output, it may be possible to log into accounts with empty passwords. 
If NULL passwords can be used, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
