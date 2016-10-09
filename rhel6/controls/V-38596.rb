# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38596 - The system must implement virtual address space randomization.'

control 'V-38596' do
  impact 0.5
  title 'The system must implement virtual address space randomization.'
  desc '
Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process\'s address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques.
'
  tag 'stig','V-38596'
  tag severity: 'medium'
  tag checkid: 'C-46153r2_chk'
  tag fixid: 'F-43543r1_fix'
  tag version: 'RHEL-06-000078'
  tag ruleid: 'SV-50397r2_rule'
  tag fixtext: '
To set the runtime status of the "kernel.randomize_va_space" kernel parameter, run the following command:

# sysctl -w kernel.randomize_va_space=2

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf":

kernel.randomize_va_space = 2
'
  tag checktext: '
The status of the "kernel.randomize_va_space" kernel parameter can be queried by running the following commands:

$ sysctl kernel.randomize_va_space
$ grep kernel.randomize_va_space /etc/sysctl.conf

The output of the command should indicate a value of at least "1" (preferably "2"). If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".
If the correct value is not returned, this is a finding.
'

# START_DESCRIBE V-38596
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
# END_DESCRIBE V-38596

end
