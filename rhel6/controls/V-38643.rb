# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38643 - There must be no world-writable files on the system.'

control 'V-38643' do
  impact 0.5
  title 'There must be no world-writable files on the system.'
  desc '
Data in world-writable files can be modified by any user on the system. In almost all circumstances, files can be configured using a combination of user and group permissions to support whatever legitimate access is needed without the risk caused by world-writable files.
'
  tag 'stig','V-38643'
  tag severity: 'medium'
  tag checkid: 'C-46202r3_chk'
  tag fixid: 'F-43591r1_fix'
  tag version: 'RHEL-06-000282'
  tag ruleid: 'SV-50444r3_rule'
  tag fixtext: '
It is generally a good idea to remove global (other) write access to a file when it is discovered. However, check with documentation for specific applications before making changes. Also, monitor for recurring world-writable files, as these may be symptoms of a misconfigured application or user account.
'
  tag checktext: '
To find world-writable files, run the following command for each local partition [PART], excluding special filesystems such as /selinux, /proc, or /sys: 

# find [PART] -xdev -type f -perm -002

If there is output, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
