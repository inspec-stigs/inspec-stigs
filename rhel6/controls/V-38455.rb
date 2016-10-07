# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38455 - The system must use a separate file system for /tmp.'

control 'V-38455' do
  impact 0.1
  title 'The system must use a separate file system for /tmp.'
  desc '
The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it.
'
  tag 'stig','V-38455'
  tag severity: 'low'
  tag checkid: 'C-45997r1_chk'
  tag fixid: 'F-43387r1_fix'
  tag version: 'RHEL-06-000001'
  tag ruleid: 'SV-50255r1_rule'
  tag fixtext: '
The "/tmp" directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.
'
  tag checktext: '
Run the following command to determine if "/tmp" is on its own partition or logical volume: 

$ mount | grep "on /tmp "

If "/tmp" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
