# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38597 - The system must limit the ability of processes to have simultaneous write and execute access to memory.'

control 'V-38597' do
  impact 0.5
  title 'The system must limit the ability of processes to have simultaneous write and execute access to memory.'
  desc '
ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process\'s memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range.
'
  tag 'stig','V-38597'
  tag severity: 'medium'
  tag checkid: 'C-46155r3_chk'
  tag fixid: 'F-43545r1_fix'
  tag version: 'RHEL-06-000079'
  tag ruleid: 'SV-50398r2_rule'
  tag fixtext: '
To set the runtime status of the "kernel.exec-shield" kernel parameter, run the following command: 

# sysctl -w kernel.exec-shield=1

If this is not the system\'s default value, add the following line to "/etc/sysctl.conf": 

kernel.exec-shield = 1
'
  tag checktext: '
The status of the "kernel.exec-shield" kernel parameter can be queried by running the following command: 

$ sysctl kernel.exec-shield
$ grep kernel.exec-shield /etc/sysctl.conf

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
If the correct value is not returned, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
