# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38683 - All accounts on the system must have unique user or account names'

control 'V-38683' do
  impact 0.1
  title 'All accounts on the system must have unique user or account names'
  desc '
Unique usernames allow for accountability on the system.
'
  tag 'stig','V-38683'
  tag severity: 'low'
  tag checkid: 'C-46245r1_chk'
  tag fixid: 'F-43632r1_fix'
  tag version: 'RHEL-06-000296'
  tag ruleid: 'SV-50484r1_rule'
  tag fixtext: '
Change usernames, or delete accounts, so each has a unique name.
'
  tag checktext: '
Run the following command to check for duplicate account names:

# pwck -rq

If there are no duplicate names, no line will be returned.
If a line is returned, this is a finding.
'

# START_DESCRIBE V-38683
  tag 'users','passwd'
  describe command('pwck -rq') do
    its('stdout') { should eq '' }
  end
# END_DESCRIBE V-38683

end
