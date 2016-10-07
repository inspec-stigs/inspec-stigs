# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38513 - The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.'

control 'V-38513' do
  impact 0.5
  title 'The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.'
  desc '
In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
'
  tag 'stig','V-38513'
  tag severity: 'medium'
  tag checkid: 'C-46070r1_chk'
  tag fixid: 'F-43460r1_fix'
  tag version: 'RHEL-06-000120'
  tag ruleid: 'SV-50314r1_rule'
  tag fixtext: '
To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/iptables": 

:INPUT DROP [0:0]
'
  tag checktext: '
Inspect the file "/etc/sysconfig/iptables" to determine the default policy for the INPUT chain. It should be set to DROP. 

# grep ":INPUT" /etc/sysconfig/iptables

If the default policy for the INPUT chain is not set to DROP, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
