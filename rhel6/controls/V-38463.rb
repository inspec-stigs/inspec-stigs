# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38463 - The system must use a separate file system for /var/log.'

control 'V-38463' do
  impact 0.1
  title 'The system must use a separate file system for /var/log.'
  desc '
Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".
'
  tag 'stig','V-38463'
  tag severity: 'low'
  tag checkid: 'C-46018r1_chk'
  tag fixid: 'F-43408r1_fix'
  tag version: 'RHEL-06-000003'
  tag ruleid: 'SV-50263r1_rule'
  tag fixtext: '
System logs are stored in the "/var/log" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it using LVM.
'
  tag checktext: '
Run the following command to determine if "/var/log" is on its own partition or logical volume: 

$ mount | grep "on /var/log "

If "/var/log" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
