# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38658 - The system must prohibit the reuse of passwords within twenty-four iterations.'

control 'V-38658' do
  impact 0.5
  title 'The system must prohibit the reuse of passwords within twenty-four iterations.'
  desc '
Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user.
'
  tag 'stig','V-38658'
  tag severity: 'medium'
  tag checkid: 'C-46219r1_chk'
  tag fixid: 'F-43608r1_fix'
  tag version: 'RHEL-06-000274'
  tag ruleid: 'SV-50459r1_rule'
  tag fixtext: '
Do not allow users to reuse recent passwords. This can be accomplished by using the "remember" option for the "pam_unix" PAM module. In the file "/etc/pam.d/system-auth", append "remember=24" to the line which refers to the "pam_unix.so" module, as shown:

password sufficient pam_unix.so [existing_options] remember=24

The DoD requirement is 24 passwords.
'
  tag checktext: '
To verify the password reuse setting is compliant, run the following command:

$ grep remember /etc/pam.d/system-auth

The output should show the following at the end of the line:

remember=24


If it does not, this is a finding.
'

# START_DESCRIBE V-38658
  tag 'pam.d','system-auth','remember'
  describe file('/etc/pam.d/system-auth') do
    its('content') { should match /pam_unix.*?remember=24/ }
  end
# END_DESCRIBE V-38658

end
