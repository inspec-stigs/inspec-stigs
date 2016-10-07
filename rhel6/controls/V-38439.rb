# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38439 - The system must provide automated support for account management functions.'

control 'V-38439' do
  impact 0.5
  title 'The system must provide automated support for account management functions.'
  desc '
A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. Enterprise environments make user account management challenging and complex. A user management process requiring administrators to manually address account management functions adds risk of potential oversight.
'
  tag 'stig','V-38439'
  tag severity: 'medium'
  tag checkid: 'C-45994r1_chk'
  tag fixid: 'F-43384r1_fix'
  tag version: 'RHEL-06-000524'
  tag ruleid: 'SV-50239r1_rule'
  tag fixtext: '
Implement an automated system for managing user accounts that minimizes the risk of errors, either intentional or deliberate.  If possible, this system should integrate with an existing enterprise user management system, such as, one based Active Directory or Kerberos.
'
  tag checktext: '
Interview the SA to determine if there is an automated system for managing user accounts, preferably integrated with an existing enterprise user management system.

If there is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
