# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38517 - The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.'

control 'V-38517' do
  impact 0.5
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.'
  desc '
Disabling TIPC protects the system against exploitation of any flaws in its implementation.
'
  tag 'stig','V-38517'
  tag severity: 'medium'
  tag checkid: 'C-46074r3_chk'
  tag fixid: 'F-43464r3_fix'
  tag version: 'RHEL-06-000127'
  tag ruleid: 'SV-50318r3_rule'
  tag fixtext: '
The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the "tipc" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install tipc /bin/true
'
  tag checktext: '
If the system is configured to prevent the loading of the "tipc" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r tipc /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
