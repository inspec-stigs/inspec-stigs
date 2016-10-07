# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38540 - The audit system must be configured to audit modifications to the systems network configuration.'

control 'V-38540' do
  impact 0.1
  title 'The audit system must be configured to audit modifications to the systems network configuration.'
  desc '
The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited.
'
  tag 'stig','V-38540'
  tag severity: 'low'
  tag checkid: 'C-46098r1_chk'
  tag fixid: 'F-43488r2_fix'
  tag version: 'RHEL-06-000182'
  tag ruleid: 'SV-50341r2_rule'
  tag fixtext: '
Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 

# audit_network_modifications
-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications
'
  tag checktext: '
To determine if the system is configured to audit changes to its network configuration, run the following command: 

auditctl -l | egrep \'(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)\'

If the system is configured to watch for network configuration changes, a line should be returned for each file specified (and "perm=wa" should be indicated for each). 
If the system is not configured to audit changes of the network configuration, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
