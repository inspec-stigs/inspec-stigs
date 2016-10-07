# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-51875 - The operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access.'

control 'V-51875' do
  impact 0.5
  title 'The operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access.'
  desc '
Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators. 
'
  tag 'stig','V-51875'
  tag severity: 'medium'
  tag checkid: 'C-54013r1_chk'
  tag fixid: 'F-56701r1_fix'
  tag version: 'RHEL-06-000372'
  tag ruleid: 'SV-66089r1_rule'
  tag fixtext: '
To configure the system to notify users of last logon/access using "pam_lastlog", add the following line immediately after "session required pam_limits.so":

session required pam_lastlog.so showfailed
'
  tag checktext: '
To ensure that last logon/access notification is configured correctly, run the following command:

# grep pam_lastlog.so /etc/pam.d/system-auth

The output should show output "showfailed". If that is not the case, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
