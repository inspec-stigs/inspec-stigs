# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38516 - The Reliable Datagram Sockets (RDS) protocol must be disabled unless required.'

control 'V-38516' do
  impact 0.1
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled unless required.'
  desc '
Disabling RDS protects the system against exploitation of any flaws in its implementation.
'
  tag 'stig','V-38516'
  tag severity: 'low'
  tag checkid: 'C-46073r3_chk'
  tag fixid: 'F-43463r4_fix'
  tag version: 'RHEL-06-000126'
  tag ruleid: 'SV-50317r3_rule'
  tag fixtext: '
The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide reliable high-bandwidth, low-latency communications between nodes in a cluster. To configure the system to prevent the "rds" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install rds /bin/true
'
  tag checktext: '
If the system is configured to prevent the loading of the "rds" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated "/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r rds /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
