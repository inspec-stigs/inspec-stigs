# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38614 - The SSH daemon must not allow authentication using an empty password.'

control 'V-38614' do
  impact 1.0
  title 'The SSH daemon must not allow authentication using an empty password.'
  desc '
Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere.
'
  tag 'stig','V-38614'
  tag severity: 'high'
  tag checkid: 'C-46172r1_chk'
  tag fixid: 'F-43562r1_fix'
  tag version: 'RHEL-06-000239'
  tag ruleid: 'SV-50415r1_rule'
  tag fixtext: '
To explicitly disallow remote login from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config":

PermitEmptyPasswords no

Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.
'
  tag checktext: '
To determine how the SSH daemon\'s "PermitEmptyPasswords" option is set, run the following command:

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set.
If the required value is not set, this is a finding.
'

# START_DESCRIBE V-38614
  tag 'sshd','PermitEmptyPasswords'
  describe sshd_config do
    its('PermitEmptyPasswords') { should eq 'no' }
  end
# END_DESCRIBE V-38614

end
