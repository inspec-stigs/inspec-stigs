# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-51363 - The system must use a Linux Security Module configured to enforce limits on system services.'

control 'V-51363' do
  impact 0.5
  title 'The system must use a Linux Security Module configured to enforce limits on system services.'
  desc '
Setting the SELinux state to enforcing ensures SELinux is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges.
'
  tag 'stig','V-51363'
  tag severity: 'medium'
  tag checkid: 'C-53703r1_chk'
  tag fixid: 'F-56165r1_fix'
  tag version: 'RHEL-06-000020'
  tag ruleid: 'SV-65573r1_rule'
  tag fixtext: '
The SELinux state should be set to "enforcing" at system boot time. In the file "/etc/selinux/config", add or correct the following line to configure the system to boot into enforcing mode:

SELINUX=enforcing
'
  tag checktext: '
Check the file "/etc/selinux/config" and ensure the following line appears:

SELINUX=enforcing

If SELINUX is not set to enforcing, this is a finding.
'

# START_DESCRIBE V-51363
  tag 'selinux','enforcing'
  describe parse_config_file('/etc/selinux/config') do
    its('SELINUX') { should eq 'enforcing' }
  end
# END_DESCRIBE V-51363

end
