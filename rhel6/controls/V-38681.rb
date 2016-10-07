# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38681 - All GIDs referenced in /etc/passwd must be defined in /etc/group'

control 'V-38681' do
  impact 0.1
  title 'All GIDs referenced in /etc/passwd must be defined in /etc/group'
  desc '
Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights.
'
  tag 'stig','V-38681'
  tag severity: 'low'
  tag checkid: 'C-46243r2_chk'
  tag fixid: 'F-43630r1_fix'
  tag version: 'RHEL-06-000294'
  tag ruleid: 'SV-50482r2_rule'
  tag fixtext: '
Add a group to the system for each GID referenced without a corresponding group.
'
  tag checktext: '
To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command: 

# pwck -r | grep \'no group\'

There should be no output. 
If there is output, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
