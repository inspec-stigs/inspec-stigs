# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38484 - The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.'

control 'V-38484' do
  impact 0.5
  title 'The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.'
  desc '
Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.

At ssh login, a user must be presented with the last successful login date and time.
'
  tag 'stig','V-38484'
  tag severity: 'medium'
  tag checkid: 'C-46041r2_chk'
  tag fixid: 'F-43431r2_fix'
  tag version: 'RHEL-06-000507'
  tag ruleid: 'SV-50285r2_rule'
  tag fixtext: '
Update the "PrintLastLog" keyword to "yes" in /etc/ssh/sshd_config:

PrintLastLog yes

While it is acceptable to remove the keyword entirely since the default action for the SSH daemon is to print the last logon date and time, it is preferred to have the value explicitly documented.
'
  tag checktext: '
Verify the value associated with the "PrintLastLog" keyword in /etc/ssh/sshd_config:

# grep -i "^PrintLastLog" /etc/ssh/sshd_config

If the "PrintLastLog" keyword is not present, this is not a finding.  If the value is not set to "yes", this is a finding.
'

# START_DESCRIBE V-38484
  describe sshd_config do
    its('PrintLastLog') { should eq 'yes' }
  end
# END_DESCRIBE V-38484

end
