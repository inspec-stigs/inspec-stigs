# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38514 - The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.'

control 'V-38514' do
  impact 0.5
  title 'The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.'
  desc '
Disabling DCCP protects the system against exploitation of any flaws in its implementation.
'
  tag 'stig','V-38514'
  tag severity: 'medium'
  tag checkid: 'C-46071r3_chk'
  tag fixid: 'F-43461r3_fix'
  tag version: 'RHEL-06-000124'
  tag ruleid: 'SV-50315r3_rule'
  tag fixtext: '
The Datagram Congestion Control Protocol (DCCP) is a relatively new transport layer protocol, designed to support streaming media and telephony. To configure the system to prevent the "dccp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install dccp /bin/true
'
  tag checktext: '
If the system is configured to prevent the loading of the "dccp" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r dccp /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
