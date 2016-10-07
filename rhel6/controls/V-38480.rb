# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38480 - Users must be warned 7 days in advance of password expiration.'

control 'V-38480' do
  impact 0.1
  title 'Users must be warned 7 days in advance of password expiration.'
  desc '
Setting the password warning age enables users to make the change at a practical time.
'
  tag 'stig','V-38480'
  tag severity: 'low'
  tag checkid: 'C-46035r1_chk'
  tag fixid: 'F-43425r1_fix'
  tag version: 'RHEL-06-000054'
  tag ruleid: 'SV-50280r1_rule'
  tag fixtext: '
To specify how many days prior to password expiration that a warning will be issued to users, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_WARN_AGE [DAYS]

The DoD requirement is 7.
'
  tag checktext: '
To check the password warning age, run the command: 

$ grep PASS_WARN_AGE /etc/login.defs

The DoD requirement is 7. 
If it is not set to the required value, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
