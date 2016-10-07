# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38655 - The noexec option must be added to removable media partitions.'

control 'V-38655' do
  impact 0.1
  title 'The noexec option must be added to removable media partitions.'
  desc '
Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise.
'
  tag 'stig','V-38655'
  tag severity: 'low'
  tag checkid: 'C-46216r1_chk'
  tag fixid: 'F-43605r1_fix'
  tag version: 'RHEL-06-000271'
  tag ruleid: 'SV-50456r1_rule'
  tag fixtext: '
The "noexec" mount option prevents the direct execution of binaries on the mounted filesystem. Users should not be allowed to execute binaries that exist on partitions mounted from removable media (such as a USB key). The "noexec" option prevents code from being executed directly from the media itself, and may therefore provide a line of defense against certain types of worms or malicious code. Add the "noexec" option to the fourth column of "/etc/fstab" for the line which controls mounting of any removable media partitions.
'
  tag checktext: '
To verify that binaries cannot be directly executed from removable media, run the following command: 

# grep noexec /etc/fstab

The output should show "noexec" in use. 
If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
