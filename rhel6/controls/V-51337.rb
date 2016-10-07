# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-51337 - The system must use a Linux Security Module at boot time.'

control 'V-51337' do
  impact 0.5
  title 'The system must use a Linux Security Module at boot time.'
  desc '
Disabling a major host protection feature, such as SELinux, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation.
'
  tag 'stig','V-51337'
  tag severity: 'medium'
  tag checkid: 'C-54007r1_chk'
  tag fixid: 'F-56147r1_fix'
  tag version: 'RHEL-06-000017'
  tag ruleid: 'SV-65547r1_rule'
  tag fixtext: '
SELinux can be disabled at boot time by an argument in "/etc/grub.conf". Remove any instances of "selinux=0" from the kernel arguments in that file to prevent SELinux from being disabled at boot. 
'
  tag checktext: '
Inspect "/etc/grub.conf" for any instances of "selinux=0" in the kernel boot arguments. Presence of "selinux=0" indicates that SELinux is disabled at boot time. If SELinux is disabled at boot time, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
